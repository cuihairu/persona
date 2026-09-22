import {
    sendNativeMessage,
    getSuggestions,
    requestFill,
    getTotp,
    copyToClipboard,
    passkeyList,
    passkeyCreate,
    passkeyAssert,
    type BridgeStatus,
    type SuggestionItem,
    type SuggestionsPayload,
    type FillPayload,
    type PasskeyCreateRequest,
    type PasskeyAssertRequest,
    type PasskeyListResponsePayload,
    type PasskeyCreateResponsePayload,
    type PasskeyAssertResponsePayload
} from './nativeBridge';
import {
    evaluateDomain,
    upsertPolicy,
    removePolicy,
    type DomainPolicy,
    type DomainAssessment
} from './domainPolicy';
import { AUTOFILL_SETTINGS_KEY, DEFAULT_AUTOFILL_SETTINGS } from './settings';

const STORAGE_KEY = 'persona_bridge_status';
const FORMS_KEY = 'persona_forms';
const POLICY_KEY = 'persona_domain_policies';
const SUGGESTIONS_KEY = 'persona_suggestions';
const DEFAULT_NATIVE_ENDPOINT = 'native:com.persona.native';

chrome.runtime.onInstalled.addListener(() => {
    console.log('Persona extension installed');
    // Seed status so the popup can show something before the first button click.
    chrome.storage.local.set({
        [STORAGE_KEY]: {
            connected: false,
            endpoint: DEFAULT_NATIVE_ENDPOINT,
            lastChecked: Date.now(),
            message: 'Bridge not contacted yet'
        },
        [POLICY_KEY]: []
    });

    chrome.storage.local.get(AUTOFILL_SETTINGS_KEY, (value) => {
        if (value?.[AUTOFILL_SETTINGS_KEY]) return;
        chrome.storage.local.set({ [AUTOFILL_SETTINGS_KEY]: DEFAULT_AUTOFILL_SETTINGS });
    });
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === 'persona_ping') {
        handleBridgePing(message?.endpoint).then(sendResponse);
        return true; // keep channel open for async response
    }

    if (message?.type === 'persona_status_request') {
        chrome.storage.local.get(STORAGE_KEY, (value) => {
            sendResponse(value?.[STORAGE_KEY]);
        });
        return true;
    }

    if (message?.type === 'persona_forms_snapshot') {
        void updateFormsSnapshot(message.host, message.forms);
        return false;
    }

    if (message?.type === 'persona_forms_request') {
        chrome.storage.local.get(FORMS_KEY, (value) => {
            sendResponse(value?.[FORMS_KEY]);
        });
        return true;
    }

    if (message?.type === 'persona_domain_policies_get') {
        getPolicies().then((policies) => sendResponse(policies));
        return true;
    }

    if (message?.type === 'persona_domain_trust') {
        handlePolicyUpdate(message.host, message.trust, message.note).then((policies) => sendResponse(policies));
        return true;
    }

    if (message?.type === 'persona_domain_remove') {
        handlePolicyRemoval(message.host).then((policies) => sendResponse(policies));
        return true;
    }

    // ============ Autofill API ============

    // Get autofill suggestions for current page
    if (message?.type === 'persona_get_suggestions') {
        handleGetSuggestions(message.origin, message.formType).then(sendResponse);
        return true;
    }

    // Request credential fill
    if (message?.type === 'persona_request_fill') {
        handleRequestFill(message.origin, message.itemId, message.userGesture).then(sendResponse);
        return true;
    }

    // Get TOTP code
    if (message?.type === 'persona_get_totp') {
        handleGetTotp(message.origin, message.itemId, message.userGesture).then(sendResponse);
        return true;
    }

    // Copy to clipboard
    if (message?.type === 'persona_copy') {
        handleCopy(message.origin, message.itemId, message.field, message.userGesture).then(sendResponse);
        return true;
    }

    // ============ Passkeys (bridge protocol v2) ============

    if (message?.type === 'persona_passkey_list') {
        handlePasskeyList(message.origin, message.rpId).then(sendResponse);
        return true;
    }

    if (message?.type === 'persona_passkey_create') {
        handlePasskeyCreate(message.request).then(sendResponse);
        return true;
    }

    if (message?.type === 'persona_passkey_assert') {
        handlePasskeyAssert(message.request).then(sendResponse);
        return true;
    }

    return false;
});

async function handleBridgePing(endpoint?: string): Promise<BridgeStatus> {
    const status = await pingAnyBridge(endpoint);
    await chrome.storage.local.set({ [STORAGE_KEY]: status });
    await broadcastStatus(status);
    return status;
}

async function pingAnyBridge(endpoint?: string): Promise<BridgeStatus> {
    // 只走 native messaging 单通道（HTTP 探测端点从未有服务端实现，已删）；
    // endpoint 参数保留以兼容 popup 传值，非 native 值一律回落默认 host
    const normalized = endpoint?.trim();
    if (normalized && normalized !== 'native' && !normalized.startsWith('native:')) {
        return pingNative(undefined);
    }
    return pingNative(normalized);
}

async function pingNative(endpoint?: string): Promise<BridgeStatus> {
    const now = Date.now();
    const host = endpoint?.startsWith('native:') ? endpoint.slice('native:'.length) : 'com.persona.native';
    const requestId = crypto.randomUUID?.() ?? String(now);
    const response = await sendNativeMessage(
        {
            type: 'status',
            request_id: requestId,
            payload: {}
        },
        host
    );

    if (!response?.ok) {
        return {
            connected: false,
            endpoint: `native:${host}`,
            lastChecked: now,
            message: response?.error ?? 'Native bridge unavailable'
        };
    }

    const locked = Boolean((response as any)?.payload?.locked);
    const activeIdentity = (response as any)?.payload?.active_identity;
    const message = locked
        ? 'Locked (set PERSONA_MASTER_PASSWORD for CLI bridge)'
        : activeIdentity
        ? `Unlocked (active=${activeIdentity})`
        : 'Unlocked';

    return {
        connected: true,
        endpoint: `native:${host}`,
        lastChecked: now,
        message,
        payload: response?.payload as any
    };
}

async function broadcastStatus(status: BridgeStatus) {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    for (const tab of tabs) {
        if (!tab.id) continue;
        chrome.tabs
            .sendMessage(tab.id, { type: 'persona_status', status })
            .catch(() => {
                /* Ignore tabs without the content script */
            });
    }
}

chrome.action.onClicked.addListener(async () => {
    await handleBridgePing();
});

async function getPolicies(): Promise<DomainPolicy[]> {
    return new Promise((resolve) => {
        chrome.storage.local.get(POLICY_KEY, (value) => resolve(value?.[POLICY_KEY] ?? []));
    });
}

async function setPolicies(policies: DomainPolicy[]): Promise<void> {
    return new Promise((resolve) => {
        chrome.storage.local.set({ [POLICY_KEY]: policies }, () => resolve());
    });
}

async function getFormsSnapshot(): Promise<
    | {
          host: string;
          forms: unknown[];
          capturedAt: number;
          assessment?: DomainAssessment;
      }
    | undefined
> {
    return new Promise((resolve) => {
        chrome.storage.local.get(FORMS_KEY, (value) => resolve(value?.[FORMS_KEY]));
    });
}

async function updateFormsSnapshot(host: string, forms: unknown[]) {
    const policies = await getPolicies();
    const assessment = evaluateDomain(host, policies);
    const payload = {
        host,
        forms,
        capturedAt: Date.now(),
        assessment
    };
    await chrome.storage.local.set({ [FORMS_KEY]: payload });
}

async function refreshAssessment() {
    const [snapshot, policies] = await Promise.all([getFormsSnapshot(), getPolicies()]);
    if (!snapshot?.host) return;
    const assessment = evaluateDomain(snapshot.host, policies);
    await chrome.storage.local.set({ [FORMS_KEY]: { ...snapshot, assessment } });
}

async function handlePolicyUpdate(host: string, trust: 'trusted' | 'blocked', note?: string) {
    const policies = await getPolicies();
    const next = upsertPolicy(policies, {
        host,
        trust,
        note,
        updatedAt: Date.now()
    });
    await setPolicies(next);
    await refreshAssessment();
    return next;
}

async function handlePolicyRemoval(host: string) {
    const policies = await getPolicies();
    const next = removePolicy(policies, host);
    await setPolicies(next);
    await refreshAssessment();
    return next;
}

// ============ Autofill Handlers ============

interface AutofillResult<T = any> {
    success: boolean;
    data?: T;
    error?: string;
}

/**
 * Get autofill suggestions for a given origin. `formType` selects the
 * suggestion pool: "login" (default, URL-matched passwords/TOTP) or "card"
 * (all active bank cards, no URL filtering).
 */
async function handleGetSuggestions(origin: string, formType = 'login'): Promise<AutofillResult<SuggestionsPayload>> {
    try {
        // Check domain policy first
        const policies = await getPolicies();
        const host = new URL(origin).hostname;
        const assessment = evaluateDomain(host, policies);

        if (assessment.risk === 'blocked') {
            return {
                success: false,
                error: 'Domain is blocked by policy'
            };
        }

        const response = await getSuggestions(origin, formType);

        if (!response.ok) {
            return {
                success: false,
                error: response.error ?? 'Failed to get suggestions'
            };
        }

        // Cache suggestions for quick access (keyed per form type so card
        // and login pools don't clobber each other)
        await chrome.storage.local.set({
            [`${SUGGESTIONS_KEY}:${formType}`]: {
                origin,
                suggestions: response.payload,
                timestamp: Date.now()
            }
        });

        return {
            success: true,
            data: response.payload
        };
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}

/**
 * Request credential fill for a specific item.
 */
async function handleRequestFill(
    origin: string,
    itemId: string,
    userGesture = true
): Promise<AutofillResult<FillPayload>> {
    try {
        // Check domain policy
        const policies = await getPolicies();
        const host = new URL(origin).hostname;
        const assessment = evaluateDomain(host, policies);

        if (assessment.risk === 'blocked') {
            return {
                success: false,
                error: 'Domain is blocked by policy'
            };
        }

        if (assessment.risk === 'suspicious') {
            return {
                success: false,
                error: `user_confirmation_required: domain flagged as suspicious (${assessment.reasons.join('; ') || host})`
            };
        }

        const response = await requestFill(origin, itemId, userGesture);

        if (!response.ok) {
            return {
                success: false,
                error: response.error ?? 'Fill request failed'
            };
        }

        return {
            success: true,
            data: response.payload
        };
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}

/**
 * Get TOTP code for a credential.
 */
async function handleGetTotp(
    origin: string,
    itemId: string,
    userGesture = true
): Promise<AutofillResult<{ code: string; remaining_seconds: number; period: number }>> {
    try {
        const policies = await getPolicies();
        const host = new URL(origin).hostname;
        const assessment = evaluateDomain(host, policies);

        if (assessment.risk === 'blocked') {
            return { success: false, error: 'Domain is blocked by policy' };
        }
        if (assessment.risk === 'suspicious') {
            return {
                success: false,
                error: `user_confirmation_required: domain flagged as suspicious (${assessment.reasons.join('; ') || host})`
            };
        }

        const response = await getTotp(origin, itemId, userGesture);

        if (!response.ok) {
            return {
                success: false,
                error: response.error ?? 'Failed to get TOTP'
            };
        }

        return {
            success: true,
            data: response.payload
        };
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}

/**
 * Copy a field to clipboard.
 */
async function handleCopy(
    origin: string,
    itemId: string,
    field: 'password' | 'username' | 'totp',
    userGesture = true
): Promise<AutofillResult<{ copied: boolean }>> {
    try {
        if (!origin) {
            return { success: false, error: 'Origin is required for copy requests' };
        }

        const policyError = await policyRejection(origin);
        if (policyError) return { success: false, error: policyError };

        const response = await copyToClipboard(origin, itemId, field, userGesture);

        if (!response.ok) {
            return {
                success: false,
                error: response.error ?? 'Copy failed'
            };
        }

        return {
            success: true,
            data: { copied: response.payload?.copied ?? false }
        };
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}

/**
 * Domain-policy gate shared by the passkey handlers: returns an error string
 * when the origin is blocked or flagged suspicious, or null to proceed.
 */
async function policyRejection(origin: string): Promise<string | null> {
    const policies = await getPolicies();
    const host = new URL(origin).hostname;
    const assessment = evaluateDomain(host, policies);
    if (assessment.risk === 'blocked') {
        return 'Domain is blocked by policy';
    }
    if (assessment.risk === 'suspicious') {
        return `user_confirmation_required: domain flagged as suspicious (${assessment.reasons.join('; ') || host})`;
    }
    return null;
}

// ============ Passkey Handlers (bridge protocol v2) ============

/**
 * List passkeys for a relying party (non-sensitive summaries).
 */
async function handlePasskeyList(
    origin: string,
    rpId?: string
): Promise<AutofillResult<PasskeyListResponsePayload>> {
    try {
        const policyError = await policyRejection(origin);
        if (policyError) return { success: false, error: policyError };

        const response = await passkeyList(origin, rpId);
        if (!response.ok) {
            return { success: false, error: response.error ?? 'Failed to list passkeys' };
        }
        return { success: true, data: response.payload };
    } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
}

/**
 * Create a passkey for the active identity (the hook's confirm dialog has
 * already run — the content script only forwards after an explicit click).
 */
async function handlePasskeyCreate(
    request: PasskeyCreateRequest
): Promise<AutofillResult<PasskeyCreateResponsePayload>> {
    try {
        const policyError = await policyRejection(request.origin);
        if (policyError) return { success: false, error: policyError };

        const response = await passkeyCreate(request);
        if (!response.ok) {
            return { success: false, error: response.error ?? 'Passkey creation failed' };
        }
        return { success: true, data: response.payload };
    } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
}

/**
 * Sign a WebAuthn assertion with a user-selected passkey.
 */
async function handlePasskeyAssert(
    request: PasskeyAssertRequest
): Promise<AutofillResult<PasskeyAssertResponsePayload>> {
    try {
        const policyError = await policyRejection(request.origin);
        if (policyError) return { success: false, error: policyError };

        const response = await passkeyAssert(request);
        if (!response.ok) {
            return { success: false, error: response.error ?? 'Passkey assertion failed' };
        }
        return { success: true, data: response.payload };
    } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
}
