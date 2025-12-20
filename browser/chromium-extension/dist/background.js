import { pingBridge } from './bridge';
import { sendNativeMessage, getSuggestions, requestFill, getTotp, copyToClipboard } from './nativeBridge';
import { evaluateDomain, upsertPolicy, removePolicy } from './domainPolicy';
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
        handleGetSuggestions(message.origin).then(sendResponse);
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
    return false;
});
async function handleBridgePing(endpoint) {
    const status = await pingAnyBridge(endpoint);
    await chrome.storage.local.set({ [STORAGE_KEY]: status });
    await broadcastStatus(status);
    return status;
}
async function pingAnyBridge(endpoint) {
    const normalized = endpoint?.trim();
    if (!normalized || normalized === 'native' || normalized.startsWith('native:')) {
        return pingNative(normalized);
    }
    return pingBridge(normalized);
}
async function pingNative(endpoint) {
    const now = Date.now();
    const host = endpoint?.startsWith('native:') ? endpoint.slice('native:'.length) : 'com.persona.native';
    const requestId = crypto.randomUUID?.() ?? String(now);
    const response = await sendNativeMessage({
        type: 'status',
        request_id: requestId,
        payload: {}
    }, host);
    if (!response?.ok) {
        return {
            connected: false,
            endpoint: `native:${host}`,
            lastChecked: now,
            message: response?.error ?? 'Native bridge unavailable'
        };
    }
    const locked = Boolean(response?.payload?.locked);
    const activeIdentity = response?.payload?.active_identity;
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
        payload: response?.payload
    };
}
async function broadcastStatus(status) {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    for (const tab of tabs) {
        if (!tab.id)
            continue;
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
async function getPolicies() {
    return new Promise((resolve) => {
        chrome.storage.local.get(POLICY_KEY, (value) => resolve(value?.[POLICY_KEY] ?? []));
    });
}
async function setPolicies(policies) {
    return new Promise((resolve) => {
        chrome.storage.local.set({ [POLICY_KEY]: policies }, () => resolve());
    });
}
async function getFormsSnapshot() {
    return new Promise((resolve) => {
        chrome.storage.local.get(FORMS_KEY, (value) => resolve(value?.[FORMS_KEY]));
    });
}
async function updateFormsSnapshot(host, forms) {
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
    if (!snapshot?.host)
        return;
    const assessment = evaluateDomain(snapshot.host, policies);
    await chrome.storage.local.set({ [FORMS_KEY]: { ...snapshot, assessment } });
}
async function handlePolicyUpdate(host, trust, note) {
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
async function handlePolicyRemoval(host) {
    const policies = await getPolicies();
    const next = removePolicy(policies, host);
    await setPolicies(next);
    await refreshAssessment();
    return next;
}
/**
 * Get autofill suggestions for a given origin.
 */
async function handleGetSuggestions(origin) {
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
        const response = await getSuggestions(origin);
        if (!response.ok) {
            return {
                success: false,
                error: response.error ?? 'Failed to get suggestions'
            };
        }
        // Cache suggestions for quick access
        await chrome.storage.local.set({
            [SUGGESTIONS_KEY]: {
                origin,
                suggestions: response.payload,
                timestamp: Date.now()
            }
        });
        return {
            success: true,
            data: response.payload
        };
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}
/**
 * Request credential fill for a specific item.
 */
async function handleRequestFill(origin, itemId, userGesture = true) {
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
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}
/**
 * Get TOTP code for a credential.
 */
async function handleGetTotp(origin, itemId, userGesture = true) {
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
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}
/**
 * Copy a field to clipboard.
 */
async function handleCopy(origin, itemId, field, userGesture = true) {
    try {
        if (!origin) {
            return { success: false, error: 'Origin is required for copy requests' };
        }
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
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}
//# sourceMappingURL=background.js.map