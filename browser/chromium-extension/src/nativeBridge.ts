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
    /** Desktop/CLI Connect server available for unlock linkage (Batch D). */
    connect_available?: boolean;
    /** Connect server port if available. */
    connect_port?: number | null;
}

export interface SuggestionItem {
    item_id: string;
    title: string;
    username_hint?: string;
    match_strength: number;
    credential_type?: string;
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
    /** Desktop/CLI Connect server available for unlock linkage (Batch D). */
    connect_available?: boolean;
    /** Connect server port if available. */
    connect_port?: number | null;
}

/** Popup/background 共用的桥状态快照（原 bridge.ts 的 HTTP 探测已删——
 * 该端点从未有服务端实现，扩展只走 native messaging 单通道）。 */
export interface BridgeStatus {
    connected: boolean;
    endpoint: string;
    lastChecked: number;
    message?: string;
    payload?: StatusPayload;
}

// ============ Passkeys (bridge protocol v2) ============

export interface PasskeyListItem {
    id: string;
    rp_id: string;
    user_name?: string;
    user_display_name?: string;
    identity_name?: string;
    created_at: number;
}

export interface PasskeyListResponsePayload {
    items: PasskeyListItem[];
}

export interface PasskeyCreateResponsePayload {
    item_id: string;
    credential_id_b64: string;
    attestation_object_b64: string;
    client_data_json_b64: string;
    transports: string[];
}

export interface PasskeyAssertResponsePayload {
    item_id: string;
    credential_id_b64: string;
    authenticator_data_b64: string;
    signature_der_b64: string;
    user_handle_b64: string;
}

/** Payload built by the MAIN-world WebAuthn hook (webauthnHook.ts). */
export interface PasskeyCreateRequest {
    origin: string;
    user_gesture: boolean;
    /** PublicKeyCredentialCreationOptions with BufferSource fields b64url-encoded */
    request_json: Record<string, any>;
    /** Raw clientDataJSON bytes the authenticator will sign over */
    client_data_json_b64: string;
}

export interface PasskeyAssertRequest {
    origin: string;
    user_gesture: boolean;
    item_id: string;
    client_data_json_b64: string;
    user_verification: boolean;
}

// ============ Vault write path (bridge protocol v4) ============

export interface FindForSaveMatch {
    item_id: string;
    name: string;
    username?: string;
}

export interface FindForSaveResponsePayload {
    matches: FindForSaveMatch[];
}

export interface SaveCredentialRequest {
    origin: string;
    user_gesture: boolean;
    /** Present ⇒ update that item's password; absent ⇒ create a new item. */
    item_id?: string;
    username?: string;
    password: string;
    name_hint?: string;
}

export interface SaveCredentialResponsePayload {
    item_id: string;
    action: 'created' | 'updated';
    name: string;
}

// ============ Password generator (bridge protocol v5) ============

export interface GeneratePasswordRequest {
    /** Total password length (default 16). */
    length?: number;
    /** Include lowercase (default true). */
    include_lowercase?: boolean;
    /** Include uppercase (default true). */
    include_uppercase?: boolean;
    /** Include digits (default true). */
    include_digits?: boolean;
    /** Include symbols (default true). */
    include_symbols?: boolean;
    /** Pronounceable alternating consonant/vowel pattern (default false). */
    pronounceable?: boolean;
    /** Diceware-style passphrase word count (3-10). Overrides length/sets. */
    words?: number;
}

export interface GeneratePasswordResponsePayload {
    password: string;
}

// ============ Cloud sync bootstrap (bridge protocol v6, M5 批1) ============

export interface SyncConnectRequest {
    /** Must come from an explicit user action — this hands out vault keys. */
    user_gesture: boolean;
}

/** `sync_connect_response`：扩展 HTTP 直连数据面的三件套 + 设备标识。
 * 敏感材料只存 chrome.storage.session（内存区），不落盘。 */
export interface SyncConnectPayload {
    server_url: string;
    token: string;
    device_id: string;
    device_name: string;
    /** group key 十六进制（与桌面 sync_group_store 同编码）。 */
    group_key_hex: string;
}

/**
 * 从本地桥取云端同步参数（配对会话 + HMAC + user_gesture 三重门禁）。
 * 成功后扩展自己直连 server 的 /api/v1/sync/*（出 native messaging 桥）。
 */
export async function syncConnect(
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<SyncConnectPayload>> {
    return sendAuthedNativeMessage<SyncConnectPayload>(
        'sync_connect',
        { user_gesture: true },
        host
    );
}

// ============ Account domain (bridge protocol v7, M5 批2) ============

export interface AccountLoginRequest {
    account_id: string;
    password: string;
    device_name: string;
    user_gesture: boolean;
}

/** `account_login_response`：SRP 编排产物。令牌本体直写宿主 keyring，
 * 不经桥协议下发——扩展只见有效期与会话指纹。 */
export interface AccountLoginPayload {
    expires_in_secs: number;
    session_key_fingerprint: string;
}

export interface AccountStatusPayload {
    has_session: boolean;
    server_configured: boolean;
}

export interface AccountLogoutPayload {
    revoked_on_server: boolean;
}

/**
 * SRP 登录账号域（challenge/verify 两跳与 M2 核验全在宿主 Rust 侧）。
 * 必须由显式用户点击触发——口令换会话令牌，属敏感操作。
 */
export async function accountLogin(
    request: Omit<AccountLoginRequest, 'user_gesture'>,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<AccountLoginPayload>> {
    return sendAuthedNativeMessage<AccountLoginPayload>(
        'account_login',
        { ...request, user_gesture: true },
        host
    );
}

/** 查询本机账号会话在场与否 + 服务器配置状态（轻量，未登录也安全）。 */
export async function accountStatus(
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<AccountStatusPayload>> {
    return sendAuthedNativeMessage<AccountStatusPayload>('account_status', {}, host);
}

// ============ Cloud sync write path (bridge protocol v7, M5 批3) ============

/** `sync_push_now_response`：与 core SyncNowReport 同字段的计数汇总。 */
export interface SyncPushNowPayload {
    pulled: number;
    materialized: number;
    conflicts: number;
    pending_identity: number;
    pushed: number;
    backfilled: number;
}

/**
 * 立即同步（写路径）：宿主跑 backfill+pull/materialize/push 周期，把主库
 * （含经 save_credential 落库的扩展侧写入）推上云。须显式用户触发。
 */
export async function syncPushNow(
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<SyncPushNowPayload>> {
    return sendAuthedNativeMessage<SyncPushNowPayload>(
        'sync_push_now',
        { user_gesture: true },
        host
    );
}

/**
 * 冲突裁决（M5 批4）：采纳并发双版本之一（adopt_op_id = 落选副本的 op id，
 * 采纳后其余版本淘汰出视图）。须显式用户触发。
 */
export async function syncResolveConflict(
    itemId: string,
    adoptOpId: string,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<{ resolved: boolean }>> {
    return sendAuthedNativeMessage<{ resolved: boolean }>(
        'sync_resolve_conflict',
        { item_id: itemId, adopt_op_id: adoptOpId, user_gesture: true },
        host
    );
}

/** 登出：宿主侧吊销服务器会话（best-effort）+ 清 keyring 令牌。 */
export async function accountLogout(
    accountId: string,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<AccountLogoutPayload>> {
    return sendAuthedNativeMessage<AccountLogoutPayload>(
        'account_logout',
        { account_id: accountId, user_gesture: true },
        host
    );
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
            protocol_version: 2,
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
    userGesture = true,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<{ code: string; remaining_seconds: number; period: number }>> {
    return sendAuthedNativeMessage(
        'get_totp',
        {
            origin,
            item_id: itemId,
            user_gesture: userGesture
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

// ============ Passkeys (bridge protocol v2) ============

/**
 * List passkeys for a relying party (non-sensitive summaries only).
 * @param rpId - Optional RP id; defaults to the origin's effective domain
 */
export async function passkeyList(
    origin: string,
    rpId?: string,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<PasskeyListResponsePayload>> {
    return sendAuthedNativeMessage<PasskeyListResponsePayload>(
        'passkey_list',
        {
            origin,
            user_gesture: true,
            rp_id: rpId
        },
        host
    );
}

/**
 * Create a passkey for the active identity.
 * @param request - Options serialized by the MAIN-world hook
 */
export async function passkeyCreate(
    request: PasskeyCreateRequest,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<PasskeyCreateResponsePayload>> {
    return sendAuthedNativeMessage<PasskeyCreateResponsePayload>('passkey_create', request, host);
}

/**
 * Sign a WebAuthn assertion with a specific passkey.
 */
export async function passkeyAssert(
    request: PasskeyAssertRequest,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<PasskeyAssertResponsePayload>> {
    return sendAuthedNativeMessage<PasskeyAssertResponsePayload>('passkey_assert', request, host);
}

// ============ Vault write path (bridge protocol v4) ============

/**
 * Look up existing password items for this host+username so the save bar can
 * offer "update" instead of piling up duplicates. Metadata only — no secrets.
 */
export async function findForSave(
    origin: string,
    username?: string,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<FindForSaveResponsePayload>> {
    return sendAuthedNativeMessage<FindForSaveResponsePayload>(
        'find_for_save',
        {
            origin,
            username
        },
        host
    );
}

/**
 * Save (create) or update a login with a password captured from a submitted
 * form. Must ride an explicit user click on the save bar — the host refuses
 * silent writes (`user_gesture_required`).
 */
export async function saveCredential(
    request: SaveCredentialRequest,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<SaveCredentialResponsePayload>> {
    return sendAuthedNativeMessage<SaveCredentialResponsePayload>('save_credential', request, host);
}

// ============ Password generator (bridge protocol v5) ============

/**
 * Generate a password or passphrase via the bridge.
 * No vault write — pure generation. Requires authenticated session.
 */
export async function generatePassword(
    request: GeneratePasswordRequest,
    host = DEFAULT_NATIVE_HOST
): Promise<NativeBridgeResponse<GeneratePasswordResponsePayload>> {
    return sendAuthedNativeMessage<GeneratePasswordResponsePayload>('generate_password', request, host);
}
