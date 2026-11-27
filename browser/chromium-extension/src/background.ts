import {
    sendNativeMessage,
    getSuggestions,
    requestFill,
    getTotp,
    copyToClipboard,
    passkeyList,
    passkeyCreate,
    passkeyAssert,
    findForSave,
    saveCredential,
    generatePassword,
    type BridgeStatus,
    type SuggestionItem,
    type SuggestionsPayload,
    type FillPayload,
    type PasskeyCreateRequest,
    type PasskeyAssertRequest,
    type PasskeyListResponsePayload,
    type PasskeyCreateResponsePayload,
    type PasskeyAssertResponsePayload,
    type FindForSaveResponsePayload,
    type SaveCredentialRequest,
    type SaveCredentialResponsePayload,
    type GeneratePasswordRequest,
    type GeneratePasswordResponsePayload
} from './nativeBridge.js';
import {
    evaluateDomain,
    upsertPolicy,
    removePolicy,
    type DomainPolicy,
    type DomainAssessment
} from './domainPolicy.js';
import {
    clearPendingSave,
    stashPendingSave,
    takePendingSave,
    type PendingSaveEntry
} from './pendingSave.js';
import { AUTOFILL_SETTINGS_KEY, DEFAULT_AUTOFILL_SETTINGS } from './settings.js';
import {
    buildMenuEntries,
    parseMenuAction,
    MENU_ROOT_ID,
    MENU_SUGGESTION_CAP,
    type MenuSuggestion
} from './contextMenu.js';

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

    refreshContextMenu(buildMenuEntries([]));
});

// ============ Right-click menu (contextMenus) ============
// The MV3 service worker is not resident, but contextMenus entries are
// browser-global and survive worker restarts. Strategy: seed the root on
// install; on every worker start rebuild the children from the cached
// suggestion pools; after each fresh suggestions fetch, rebuild again.
// Remove-all + recreate (rather than incremental updates) sidesteps the
// duplicate-id errors a restarted worker would otherwise hit mid-flight.

interface CachedSuggestionPool {
    origin: string;
    suggestions: SuggestionsPayload;
    timestamp: number;
}

function cachedMenuSuggestions(): Promise<MenuSuggestion[]> {
    return new Promise((resolve) => {
        chrome.storage.local.get([`${SUGGESTIONS_KEY}:login`, `${SUGGESTIONS_KEY}:card`], (value) => {
            const login = value?.[`${SUGGESTIONS_KEY}:login`] as CachedSuggestionPool | undefined;
            const card = value?.[`${SUGGESTIONS_KEY}:card`] as CachedSuggestionPool | undefined;
            const items = [...(login?.suggestions?.items ?? []), ...(card?.suggestions?.items ?? [])];
            resolve(items.slice(0, MENU_SUGGESTION_CAP));
        });
    });
}

function refreshContextMenu(entries: ReturnType<typeof buildMenuEntries>): void {
    if (!chrome.contextMenus) return;
    chrome.contextMenus.removeAll(() => {
        for (const entry of entries) {
            chrome.contextMenus.create(
                {
                    id: entry.id,
                    title: entry.title,
                    parentId: entry.parentId,
                    contexts: ['all']
                },
                () => void chrome.runtime.lastError // swallow duplicate-id races; the next rebuild wins
            );
        }
    });
}

async function rebuildContextMenuFromCache(): Promise<void> {
    refreshContextMenu(buildMenuEntries(await cachedMenuSuggestions()));
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
    const action = parseMenuAction(typeof info.menuItemId === 'string' ? info.menuItemId : '');
    if (!action || !tab?.id) return;
    const origin = tab.url ?? info.pageUrl ?? '';

    if (action.action === 'popup') {
        // openPopup is Chrome 127+; on older builds fall back to the in-page
        // search overlay so the entry never dead-ends
        const openPopup = (chrome.action as { openPopup?: () => void }).openPopup;
        if (typeof openPopup === 'function') {
            openPopup.call(chrome.action);
        } else {
            chrome.tabs.sendMessage(tab.id, { type: 'persona_open_search' }).catch(() => {});
        }
        return;
    }

    if (action.action === 'fill') {
        const type = action.kind === 'totp'
            ? 'persona_popup_fill_totp'
            : action.kind === 'card'
                ? 'persona_popup_fill_card'
                : 'persona_popup_fill_password';
        chrome.tabs.sendMessage(tab.id, { type, itemId: action.itemId }).catch(() => {});
        return;
    }

    // copy rides the same native clipboard path as the popup copy button
    // (right-click is a user gesture)
    void handleCopy(origin, action.itemId, action.kind, true);
});

void rebuildContextMenuFromCache();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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
        // The content script runs in every frame (batch B); frameId 0 is the
        // top document. Snapshots are kept per frame so an ad iframe can't
        // overwrite what the popup shows for the page.
        void updateFormsSnapshot(message.host, message.forms, sender?.frameId ?? 0);
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

    // ============ Vault write path (bridge protocol v4) ============

    if (message?.type === 'persona_find_for_save') {
        handleFindForSave(message.origin, message.username).then(sendResponse);
        return true;
    }

    if (message?.type === 'persona_save_credential') {
        handleSaveCredential(message.request).then(sendResponse);
        return true;
    }

    // ============ Password generator (bridge protocol v5) ============

    if (message?.type === 'persona_generate_password') {
        handleGeneratePassword(message.request).then(sendResponse);
        return true;
    }

    // Pending-save hand-off across navigations (memory-backed session area).
    if (message?.type === 'persona_stash_pending_save') {
        handleStashPendingSave(message.entry)
            .then((result) => sendResponse({ success: true, data: result }))
            .catch((error) =>
                sendResponse({
                    success: false,
                    error: error instanceof Error ? error.message : 'Unknown error'
                })
            );
        return true;
    }

    if (message?.type === 'persona_take_pending_save') {
        takePendingSave(message.origin)
            .then((entry) => sendResponse({ success: true, data: entry }))
            .catch(() => sendResponse({ success: true, data: null }));
        return true;
    }

    if (message?.type === 'persona_clear_pending_save') {
        clearPendingSave()
            .then(() => sendResponse({ success: true }))
            .catch(() => sendResponse({ success: true }));
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
    // the native messaging channel is the only one (the HTTP probe endpoint never had a server implementation and was removed);
    // the endpoint parameter is kept for compatibility with the value the popup passes — any non-native value falls back to the default host
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

// MV3 commands API: global keyboard shortcut to open mini search
chrome.commands.onCommand.addListener((command) => {
    if (command === 'open_search') {
        void openSearchOnActiveTab();
    }
});

async function openSearchOnActiveTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs?.[0];
    if (!tab?.id) return;
    // Send message to content script to open search overlay
    chrome.tabs.sendMessage(tab.id, { type: 'persona_open_search' }).catch(() => {
        // Content script not loaded (e.g., chrome:// page) — silently ignore
    });
}

async function getPolicies(): Promise<DomainPolicy[]> {
    return new Promise((resolve) => {
        chrome.storage.local.get(POLICY_KEY, (value) => resolve((value?.[POLICY_KEY] as DomainPolicy[] | undefined) ?? []));
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
        // explicit assertion needed after @types/chrome narrowed the storage.get callback index type (get/set share the same shape, the contract lives in this function's signature)
        chrome.storage.local.get(FORMS_KEY, (value) =>
            resolve(value?.[FORMS_KEY] as { host: string; forms: unknown[]; capturedAt: number; assessment?: DomainAssessment } | undefined),
        );
    });
}

const MAX_TRACKED_FRAMES = 8;

interface FrameSnapshot {
    host: string;
    forms: unknown[];
    capturedAt: number;
}

/**
 * Store the newest snapshot per frame and derive the payload the popup reads.
 * The top frame (id 0) always wins when it has reported; otherwise the most
 * recent frame does, so a page whose form lives in an iframe still shows
 * something useful before/without a top-frame scan. Frames are pruned to a
 * handful of newest entries — ad-heavy pages can host dozens.
 */
async function updateFormsSnapshot(host: string, forms: unknown[], frameId: number) {
    const policies = await getPolicies();
    const assessment = evaluateDomain(host, policies);
    const existing = (await getFormsSnapshot()) as
        | (Record<string, any> & { frames?: Record<string, FrameSnapshot> })
        | undefined;
    const frames: Record<string, FrameSnapshot> = { ...(existing?.frames ?? {}) };
    frames[String(frameId)] = { host, forms, capturedAt: Date.now() };

    const keys = Object.keys(frames);
    if (keys.length > MAX_TRACKED_FRAMES) {
        const newestFirst = keys.sort(
            (a, b) => (frames[b].capturedAt ?? 0) - (frames[a].capturedAt ?? 0)
        );
        const kept = newestFirst.slice(0, MAX_TRACKED_FRAMES);
        if (frames['0']) kept.push('0');
        for (const key of keys) {
            if (!kept.includes(key)) delete frames[key];
        }
    }

    const primary = frames['0'] ?? frames[Object.keys(frames).sort(
        (a, b) => (frames[b].capturedAt ?? 0) - (frames[a].capturedAt ?? 0)
    )[0]];
    if (!primary) return;

    const payload = {
        host: primary.host,
        forms: primary.forms,
        capturedAt: primary.capturedAt,
        assessment: evaluateDomain(primary.host, policies),
        frameCount: Object.keys(frames).length
    };
    await chrome.storage.local.set({ [FORMS_KEY]: { ...payload, frames } });
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

        // fresh pools landed: the right-click children follow them
        void rebuildContextMenuFromCache();

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

// ============ Vault write path (bridge protocol v4) ============

/**
 * Existing password items for this host+username (metadata only) — lets the
 * save bar offer "update" instead of stacking duplicates.
 */
async function handleFindForSave(
    origin: string,
    username?: string
): Promise<AutofillResult<FindForSaveResponsePayload>> {
    try {
        const policyError = await policyRejection(origin);
        if (policyError) return { success: false, error: policyError };

        const response = await findForSave(origin, username);
        if (!response.ok) {
            return { success: false, error: response.error ?? 'Failed to look up existing items' };
        }
        return { success: true, data: response.payload };
    } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
}

/**
 * Save/update a captured login. Same strict gate as fills (blocked AND
 * suspicious both refuse): writing a password to a phishing lookalike is as
 * harmful as filling one there. The explicit save-bar click is the user
 * gesture the host requires.
 */
/**
 * Hold a captured proposal for the next page load of the same origin. The
 * content script only stashes after its own policy gate passed, and the
 * entry is origin-bound + TTL-bounded in `pendingSave.ts`, so this stays a
 * plain memory write.
 */
async function handleStashPendingSave(entry: PendingSaveEntry) {
    if (!entry?.origin || !entry?.password) return { duplicate: false };
    return stashPendingSave(entry);
}

async function handleSaveCredential(
    request: SaveCredentialRequest
): Promise<AutofillResult<SaveCredentialResponsePayload>> {
    try {
        const policyError = await policyRejection(request.origin);
        if (policyError) return { success: false, error: policyError };

        const response = await saveCredential(request);
        if (!response.ok) {
            return { success: false, error: response.error ?? 'Save failed' };
        }
        return { success: true, data: response.payload };
    } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
}

// ============ Password generator (bridge protocol v5) ============

async function handleGeneratePassword(
    request: GeneratePasswordRequest
): Promise<AutofillResult<GeneratePasswordResponsePayload>> {
    try {
        // No domain policy gate for generation (no vault write), but still
        // require authenticated session via nativeBridge.sendAuthedNativeMessage.
        const response = await generatePassword(request);
        if (!response.ok) {
            return { success: false, error: response.error ?? 'Generation failed' };
        }
        return { success: true, data: response.payload };
    } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
}
