const DEFAULT_NATIVE_HOST = 'com.persona.native';
const PAIRING_STORAGE_KEY = 'persona_native_pairing_v1';
function generateRequestId() {
    return crypto.randomUUID?.() ?? String(Date.now());
}
function storageGet(key) {
    return new Promise((resolve) => {
        chrome.storage.local.get(key, (value) => resolve(value?.[key]));
    });
}
function storageSet(key, value) {
    return new Promise((resolve) => {
        chrome.storage.local.set({ [key]: value }, () => resolve());
    });
}
async function loadPairingState() {
    const existing = await storageGet(PAIRING_STORAGE_KEY);
    if (existing?.clientInstanceId)
        return existing;
    const clientInstanceId = crypto.randomUUID?.() ?? String(Date.now());
    const state = { clientInstanceId };
    await storageSet(PAIRING_STORAGE_KEY, state);
    return state;
}
async function savePairingState(patch) {
    const existing = await loadPairingState();
    const next = { ...existing, ...patch };
    for (const key of Object.keys(next)) {
        if (next[key] === undefined)
            delete next[key];
    }
    await storageSet(PAIRING_STORAGE_KEY, next);
    return next;
}
export async function getPairingState() {
    return loadPairingState();
}
function canonicalizeJson(value) {
    if (Array.isArray(value))
        return value.map(canonicalizeJson);
    if (value && typeof value === 'object') {
        const out = {};
        for (const key of Object.keys(value).sort()) {
            out[key] = canonicalizeJson(value[key]);
        }
        return out;
    }
    return value;
}
function base64UrlEncode(bytes) {
    let binary = '';
    for (const b of bytes)
        binary += String.fromCharCode(b);
    const b64 = btoa(binary);
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function base64UrlDecodeToBytes(b64url) {
    const padded = b64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(b64url.length / 4) * 4, '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++)
        bytes[i] = binary.charCodeAt(i);
    return bytes;
}
async function hmacSha256Base64Url(keyBytes, message) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
    return base64UrlEncode(new Uint8Array(sig));
}
async function buildAuth(kind, requestId, payload, sessionId, pairingKeyB64) {
    const tsMs = Date.now();
    const nonce = crypto.randomUUID?.() ?? String(tsMs);
    const payloadJson = JSON.stringify(canonicalizeJson(payload ?? {}));
    const signingInput = `${kind}\n${requestId}\n${payloadJson}\n${sessionId}\n${tsMs}\n${nonce}`;
    const keyBytes = base64UrlDecodeToBytes(pairingKeyB64);
    const signature = await hmacSha256Base64Url(keyBytes, signingInput);
    return { session_id: sessionId, ts_ms: tsMs, nonce, signature };
}
export async function sendNativeMessage(message, host = DEFAULT_NATIVE_HOST) {
    return new Promise((resolve) => {
        try {
            chrome.runtime.sendNativeMessage(host, message, (response) => {
                const err = chrome.runtime.lastError;
                if (err) {
                    resolve({
                        ok: false,
                        error: err.message
                    });
                    return;
                }
                resolve((response ?? {}));
            });
        }
        catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            resolve({ ok: false, error: msg });
        }
    });
}
/**
 * Send hello handshake to the native bridge.
 */
export async function hello(host = DEFAULT_NATIVE_HOST) {
    const state = await loadPairingState();
    const response = await sendNativeMessage({
        type: 'hello',
        request_id: generateRequestId(),
        payload: {
            extension_id: chrome.runtime.id,
            extension_version: chrome.runtime.getManifest().version,
            protocol_version: 1,
            client_instance_id: state.clientInstanceId
        }
    }, host);
    if (response?.ok && response?.payload?.session_id) {
        const payload = response.payload;
        await savePairingState({
            sessionId: payload.session_id ?? undefined,
            sessionExpiresAtMs: payload.session_expires_at_ms ?? undefined
        });
    }
    return response;
}
/**
 * Get vault status (locked/unlocked, active identity).
 */
export async function getStatus(host = DEFAULT_NATIVE_HOST) {
    return sendNativeMessage({
        type: 'status',
        request_id: generateRequestId(),
        payload: {}
    }, host);
}
export async function requestPairingCode(host = DEFAULT_NATIVE_HOST) {
    const state = await loadPairingState();
    const response = await sendNativeMessage({
        type: 'pairing_request',
        request_id: generateRequestId(),
        payload: {
            extension_id: chrome.runtime.id,
            client_instance_id: state.clientInstanceId
        }
    }, host);
    if (response?.ok && response?.payload?.code) {
        const payload = response.payload;
        await savePairingState({
            lastPairingCode: payload.code,
            lastPairingExpiresAtMs: payload.expires_at_ms
        });
    }
    return response;
}
export async function finalizePairing(code, host = DEFAULT_NATIVE_HOST) {
    const state = await loadPairingState();
    const response = await sendNativeMessage({
        type: 'pairing_finalize',
        request_id: generateRequestId(),
        payload: {
            extension_id: chrome.runtime.id,
            client_instance_id: state.clientInstanceId,
            code
        }
    }, host);
    if (response?.ok && response?.payload?.pairing_key_b64) {
        const payload = response.payload;
        await savePairingState({
            pairingKeyB64: payload.pairing_key_b64,
            sessionId: payload.session_id,
            sessionExpiresAtMs: payload.session_expires_at_ms,
            lastPairingCode: undefined,
            lastPairingExpiresAtMs: undefined
        });
    }
    return response;
}
async function ensureSession(host = DEFAULT_NATIVE_HOST) {
    const state = await loadPairingState();
    if (!state.pairingKeyB64) {
        return state;
    }
    const now = Date.now();
    const expiresAt = state.sessionExpiresAtMs ?? 0;
    const hasValid = Boolean(state.sessionId) && expiresAt > now + 60000; // refresh 1min early
    if (hasValid)
        return state;
    await hello(host);
    return loadPairingState();
}
async function sendAuthedNativeMessage(kind, payload, host = DEFAULT_NATIVE_HOST) {
    const requestId = generateRequestId();
    const state = await ensureSession(host);
    if (!state.pairingKeyB64 || !state.sessionId) {
        return { ok: false, error: 'pairing_required' };
    }
    const auth = await buildAuth(kind, requestId, payload, state.sessionId, state.pairingKeyB64);
    return sendNativeMessage({
        type: kind,
        request_id: requestId,
        payload,
        auth
    }, host);
}
/**
 * Get autofill suggestions for the given origin.
 */
export async function getSuggestions(origin, formType = 'login', host = DEFAULT_NATIVE_HOST) {
    return sendAuthedNativeMessage('get_suggestions', {
        origin,
        form_type: formType
    }, host);
}
/**
 * Request credential fill for a specific item.
 * @param origin - Page origin (e.g., "https://github.com")
 * @param itemId - UUID of the credential to fill
 * @param userGesture - Whether this was triggered by explicit user action
 */
export async function requestFill(origin, itemId, userGesture = true, host = DEFAULT_NATIVE_HOST) {
    return sendAuthedNativeMessage('request_fill', {
        origin,
        item_id: itemId,
        user_gesture: userGesture
    }, host);
}
/**
 * Request TOTP code for a specific item.
 */
export async function getTotp(origin, itemId, host = DEFAULT_NATIVE_HOST) {
    return sendAuthedNativeMessage('get_totp', {
        origin,
        item_id: itemId
    }, host);
}
/**
 * Request copy to clipboard (handled by native app).
 */
export async function copyToClipboard(origin, itemId, field, userGesture = true, host = DEFAULT_NATIVE_HOST) {
    return sendAuthedNativeMessage('copy', {
        origin,
        item_id: itemId,
        field,
        user_gesture: userGesture
    }, host);
}
//# sourceMappingURL=nativeBridge.js.map