export interface NativeBridgeResponse<T = any> {
    request_id?: string;
    type?: string;
    ok?: boolean;
    error?: string;
    payload?: T;
}

export interface HelloResponsePayload {
    server_version?: string;
    capabilities?: string[];
    pairing_required?: boolean;
    paired?: boolean;
    session_id?: string | null;
    session_expires_at_ms?: number | null;
}

export interface SuggestionItem {
    item_id: string;
    title: string;
    username_hint?: string;
    match_strength: number;
}

export interface SuggestionsPayload {
    items: SuggestionItem[];
    suggesting_for: string;
}

export interface FillPayload {
    username?: string;
    password?: string;
}

export interface StatusPayload {
    locked: boolean;
    active_identity?: string;
    active_identity_name?: string;
}

const DEFAULT_NATIVE_HOST = 'com.persona.native';
const PAIRING_STORAGE_KEY = 'persona_native_pairing_v1';

function generateRequestId(): string {
    return crypto.randomUUID?.() ?? String(Date.now());
}

interface PairingState {
    clientInstanceId: string;
    pairingKeyB64?: string;
    sessionId?: string;
    sessionExpiresAtMs?: number;
    lastPairingCode?: string;
    lastPairingExpiresAtMs?: number;
}

function storageGet<T>(key: string): Promise<T | undefined> {
    return new Promise((resolve) => {
        chrome.storage.local.get(key, (value) => resolve(value?.[key] as T | undefined));
    });
}

function storageSet<T>(key: string, value: T): Promise<void> {
    return new Promise((resolve) => {
        chrome.storage.local.set({ [key]: value }, () => resolve());
    });
}

async function loadPairingState(): Promise<PairingState> {
    const existing = await storageGet<PairingState>(PAIRING_STORAGE_KEY);
    if (existing?.clientInstanceId) return existing;
    const clientInstanceId = crypto.randomUUID?.() ?? String(Date.now());
    const state: PairingState = { clientInstanceId };
    await storageSet(PAIRING_STORAGE_KEY, state);
    return state;
}

async function savePairingState(patch: Partial<PairingState>): Promise<PairingState> {
    const existing = await loadPairingState();
    const next: any = { ...existing, ...patch };
    for (const key of Object.keys(next)) {
        if (next[key] === undefined) delete next[key];
    }
    await storageSet(PAIRING_STORAGE_KEY, next);
    return next as PairingState;
}

export async function getPairingState(): Promise<PairingState> {
    return loadPairingState();
}

function canonicalizeJson(value: any): any {
    if (Array.isArray(value)) return value.map(canonicalizeJson);
    if (value && typeof value === 'object') {
        const out: any = {};
        for (const key of Object.keys(value).sort()) {
            out[key] = canonicalizeJson(value[key]);
        }
        return out;
    }
    return value;
}

function base64UrlEncode(bytes: Uint8Array): string {
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    const b64 = btoa(binary);
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecodeToBytes(b64url: string): Uint8Array {
    const padded = b64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(b64url.length / 4) * 4, '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

async function hmacSha256Base64Url(keyBytes: Uint8Array, message: string): Promise<string> {
    const key = await crypto.subtle.importKey(
        'raw',
        keyBytes as unknown as BufferSource,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
    return base64UrlEncode(new Uint8Array(sig));
}

async function buildAuth(
    kind: string,
    requestId: string,
    payload: any,
    sessionId: string,
    pairingKeyB64: string
): Promise<{ session_id: string; ts_ms: number; nonce: string; signature: string }> {
    const tsMs = Date.now();
    const nonce = crypto.randomUUID?.() ?? String(tsMs);
    const payloadJson = JSON.stringify(canonicalizeJson(payload ?? {}));
    const signingInput = `${kind}\n${requestId}\n${payloadJson}\n${sessionId}\n${tsMs}\n${nonce}`;
    const keyBytes = base64UrlDecodeToBytes(pairingKeyB64);
    const signature = await hmacSha256Base64Url(keyBytes, signingInput);
    return { session_id: sessionId, ts_ms: tsMs, nonce, signature };
}

export async function sendNativeMessage<T = any>(
    message: Record<string, any>,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<T>> {
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
                resolve((response ?? {}) as NativeBridgeResponse<T>);
            });
        } catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            resolve({ ok: false, error: msg });
        }
    });
}

/**
 * Send hello handshake to the native bridge.
 */
export async function hello(host = DEFAULT_NATIVE_HOST): Promise<NativeBridgeResponse<HelloResponsePayload>> {
    const state = await loadPairingState();
    const response = await sendNativeMessage<HelloResponsePayload>({
        type: 'hello',
        request_id: generateRequestId(),
        payload: {
            extension_id: chrome.runtime.id,
            extension_version: chrome.runtime.getManifest().version,
            protocol_version: 1,
            client_instance_id: state.clientInstanceId
        }
    }, host);

    if (response?.ok && (response as any)?.payload?.session_id) {
        const payload = (response as any).payload as HelloResponsePayload;
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
export async function getStatus(host = DEFAULT_NATIVE_HOST): Promise<NativeBridgeResponse<StatusPayload>> {
    return sendNativeMessage<StatusPayload>({
        type: 'status',
        request_id: generateRequestId(),
        payload: {}
    }, host);
}

export async function requestPairingCode(
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<{ code: string; expires_at_ms: number; approval_command: string }>> {
    const state = await loadPairingState();
    const response = await sendNativeMessage({
        type: 'pairing_request',
        request_id: generateRequestId(),
        payload: {
            extension_id: chrome.runtime.id,
            client_instance_id: state.clientInstanceId
        }
    }, host);

    if (response?.ok && (response as any)?.payload?.code) {
        const payload = (response as any).payload as any;
        await savePairingState({
            lastPairingCode: payload.code,
            lastPairingExpiresAtMs: payload.expires_at_ms
        });
    }

    return response as any;
}

export async function finalizePairing(
    code: string,
    host = DEFAULT_NATIVE_HOST
): Promise<
    NativeBridgeResponse<{
        paired: boolean;
        pairing_key_b64: string;
        session_id: string;
        session_expires_at_ms: number;
    }>
> {
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

    if (response?.ok && (response as any)?.payload?.pairing_key_b64) {
        const payload = (response as any).payload as any;
        await savePairingState({
            pairingKeyB64: payload.pairing_key_b64,
            sessionId: payload.session_id,
            sessionExpiresAtMs: payload.session_expires_at_ms,
            lastPairingCode: undefined,
            lastPairingExpiresAtMs: undefined
        });
    }

    return response as any;
}

async function ensureSession(host = DEFAULT_NATIVE_HOST): Promise<PairingState> {
    const state = await loadPairingState();
    if (!state.pairingKeyB64) {
        return state;
    }

    const now = Date.now();
    const expiresAt = state.sessionExpiresAtMs ?? 0;
    const hasValid = Boolean(state.sessionId) && expiresAt > now + 60_000; // refresh 1min early
    if (hasValid) return state;

    await hello(host);
    return loadPairingState();
}

async function sendAuthedNativeMessage<T = any>(
    kind: string,
    payload: any,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<T>> {
    const requestId = generateRequestId();
    const state = await ensureSession(host);

    if (!state.pairingKeyB64 || !state.sessionId) {
        return { ok: false, error: 'pairing_required' };
    }

    const auth = await buildAuth(kind, requestId, payload, state.sessionId, state.pairingKeyB64);
    return sendNativeMessage<T>(
        {
            type: kind,
            request_id: requestId,
            payload,
            auth
        },
        host
    );
}

/**
 * Get autofill suggestions for the given origin.
 */
export async function getSuggestions(
    origin: string,
    formType = 'login',
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<SuggestionsPayload>> {
    return sendAuthedNativeMessage<SuggestionsPayload>(
        'get_suggestions',
        {
            origin,
            form_type: formType
        },
        host
    );
}

/**
 * Request credential fill for a specific item.
 * @param origin - Page origin (e.g., "https://github.com")
 * @param itemId - UUID of the credential to fill
 * @param userGesture - Whether this was triggered by explicit user action
 */
export async function requestFill(
    origin: string,
    itemId: string,
    userGesture = true,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<FillPayload>> {
    return sendAuthedNativeMessage<FillPayload>(
        'request_fill',
        {
            origin,
            item_id: itemId,
            user_gesture: userGesture
        },
        host
    );
}

/**
 * Request TOTP code for a specific item.
 */
export async function getTotp(
    origin: string,
    itemId: string,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<{ code: string; remaining_seconds: number; period: number }>> {
    return sendAuthedNativeMessage(
        'get_totp',
        {
            origin,
            item_id: itemId
        },
        host
    );
}

/**
 * Request copy to clipboard (handled by native app).
 */
export async function copyToClipboard(
    origin: string,
    itemId: string,
    field: 'password' | 'username' | 'totp',
    userGesture = true,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<{ copied: boolean; clear_after_seconds?: number }>> {
    return sendAuthedNativeMessage(
        'copy',
        {
            origin,
            item_id: itemId,
            field,
            user_gesture: userGesture
        },
        host
    );
}
