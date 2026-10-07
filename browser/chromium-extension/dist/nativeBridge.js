/**
 * 从本地桥取云端同步参数（配对会话 + HMAC + user_gesture 三重门禁）。
 * 成功后扩展自己直连 server 的 /api/v1/sync/*（出 native messaging 桥）。
 */
export async function syncConnect(host = defaultNativeHost()) {
    return sendAuthedNativeMessage('sync_connect', { user_gesture: true }, host);
}
/**
 * SRP 登录账号域（challenge/verify 两跳与 M2 核验全在宿主 Rust 侧）。
 * 必须由显式用户点击触发——口令换会话令牌，属敏感操作。
 */
export async function accountLogin(request, host = defaultNativeHost()) {
    return sendAuthedNativeMessage('account_login', { ...request, user_gesture: true }, host);
}
/** 查询本机账号会话在场与否 + 服务器配置状态（轻量，未登录也安全）。 */
export async function accountStatus(host = defaultNativeHost()) {
    return sendAuthedNativeMessage('account_status', {}, host);
}
/**
 * 立即同步（写路径）：宿主跑 backfill+pull/materialize/push 周期，把主库
 * （含经 save_credential 落库的扩展侧写入）推上云。须显式用户触发。
 */
export async function syncPushNow(host = defaultNativeHost()) {
    return sendAuthedNativeMessage('sync_push_now', { user_gesture: true }, host);
}
/**
 * 冲突裁决（M5 批4）：采纳并发双版本之一（adopt_op_id = 落选副本的 op id，
 * 采纳后其余版本淘汰出视图）。须显式用户触发。
 */
export async function syncResolveConflict(itemId, adoptOpId, host = defaultNativeHost()) {
    return sendAuthedNativeMessage('sync_resolve_conflict', { item_id: itemId, adopt_op_id: adoptOpId, user_gesture: true }, host);
}
/** 登出：宿主侧吊销服务器会话（best-effort）+ 清 keyring 令牌。 */
export async function accountLogout(accountId, host = defaultNativeHost()) {
    return sendAuthedNativeMessage('account_logout', { account_id: accountId, user_gesture: true }, host);
}
const DEFAULT_NATIVE_HOST = 'com.persona.native';
// ---- 传输层平台适配（chromium 与 Safari 同份，M5 批5a）----
// chromium：NMH stdio 桥（com.persona.native，每请求新进程）。
// Safari：browser.runtime.sendNativeMessage 把同一份 JSON 报文交给宿主 app
// 的 SafariWebExtensionHandler（宿主进程代为拉起 `persona bridge`）——
// 报文格式与桥协议完全同构，只有 host 名（app bundle id）与全局对象
// （browser 优先于 chrome）分叉，协议层零改动。
let nativeHostOverride = null;
/** Safari 宿主 bundle id 与 chromium NMH 名不同；扩展入口按平台注入，
 * 传 null 恢复 chromium 默认。 */
export function setNativeHost(host) {
    nativeHostOverride = host;
}
function defaultNativeHost() {
    return nativeHostOverride ?? DEFAULT_NATIVE_HOST;
}
/** browser.*（Safari/标准 WebExtension）优先，chrome.*（chromium）兜底。 */
function extensionRuntime() {
    const g = globalThis;
    const candidate = g.browser?.runtime?.sendNativeMessage ? g.browser : g.chrome;
    if (!candidate?.runtime?.sendNativeMessage) {
        throw new Error('native_messaging_unavailable');
    }
    return candidate;
}
const PAIRING_STORAGE_KEY = 'persona_native_pairing_v1';
function generateRequestId() {
    return crypto.randomUUID?.() ?? String(Date.now());
}
/** 全局 WebExtension 命名空间：browser（Safari/标准）优先，chrome（chromium）兜底。 */
function extensionGlobal() {
    const g = globalThis;
    return g.browser ?? g.chrome;
}
function storageGet(key) {
    return new Promise((resolve) => {
        extensionGlobal().storage.local.get(key, (value) => resolve(value?.[key]));
    });
}
function storageSet(key, value) {
    return new Promise((resolve) => {
        extensionGlobal().storage.local.set({ [key]: value }, () => resolve());
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
export async function sendNativeMessage(message, host = defaultNativeHost()) {
    return new Promise((resolve) => {
        let runtime;
        try {
            runtime = extensionRuntime();
        }
        catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            resolve({ ok: false, error: msg });
            return;
        }
        try {
            runtime.runtime.sendNativeMessage(host, message, (response) => {
                const err = runtime.runtime.lastError;
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
export async function hello(host = defaultNativeHost()) {
    const state = await loadPairingState();
    const response = await sendNativeMessage({
        type: 'hello',
        request_id: generateRequestId(),
        payload: {
            extension_id: extensionGlobal().runtime.id,
            extension_version: extensionGlobal().runtime.getManifest().version,
            protocol_version: 2,
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
export async function getStatus(host = defaultNativeHost()) {
    return sendNativeMessage({
        type: 'status',
        request_id: generateRequestId(),
        payload: {}
    }, host);
}
export async function requestPairingCode(host = defaultNativeHost()) {
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
export async function finalizePairing(code, host = defaultNativeHost()) {
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
async function ensureSession(host = defaultNativeHost()) {
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
async function sendAuthedNativeMessage(kind, payload, host = defaultNativeHost()) {
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
export async function getSuggestions(origin, formType = 'login', host = defaultNativeHost()) {
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
export async function requestFill(origin, itemId, userGesture = true, host = defaultNativeHost()) {
    return sendAuthedNativeMessage('request_fill', {
        origin,
        item_id: itemId,
        user_gesture: userGesture
    }, host);
}
/**
 * Request TOTP code for a specific item.
 */
export async function getTotp(origin, itemId, userGesture = true, host = defaultNativeHost()) {
    return sendAuthedNativeMessage('get_totp', {
        origin,
        item_id: itemId,
        user_gesture: userGesture
    }, host);
}
/**
 * Request copy to clipboard (handled by native app).
 */
export async function copyToClipboard(origin, itemId, field, userGesture = true, host = defaultNativeHost()) {
    return sendAuthedNativeMessage('copy', {
        origin,
        item_id: itemId,
        field,
        user_gesture: userGesture
    }, host);
}
// ============ Passkeys (bridge protocol v2) ============
/**
 * List passkeys for a relying party (non-sensitive summaries only).
 * @param rpId - Optional RP id; defaults to the origin's effective domain
 */
export async function passkeyList(origin, rpId, host = defaultNativeHost()) {
    return sendAuthedNativeMessage('passkey_list', {
        origin,
        user_gesture: true,
        rp_id: rpId
    }, host);
}
/**
 * Create a passkey for the active identity.
 * @param request - Options serialized by the MAIN-world hook
 */
export async function passkeyCreate(request, host = defaultNativeHost()) {
    return sendAuthedNativeMessage('passkey_create', request, host);
}
/**
 * Sign a WebAuthn assertion with a specific passkey.
 */
export async function passkeyAssert(request, host = defaultNativeHost()) {
    return sendAuthedNativeMessage('passkey_assert', request, host);
}
// ============ Vault write path (bridge protocol v4) ============
/**
 * Look up existing password items for this host+username so the save bar can
 * offer "update" instead of piling up duplicates. Metadata only — no secrets.
 */
export async function findForSave(origin, username, host = defaultNativeHost()) {
    return sendAuthedNativeMessage('find_for_save', {
        origin,
        username
    }, host);
}
/**
 * Save (create) or update a login with a password captured from a submitted
 * form. Must ride an explicit user click on the save bar — the host refuses
 * silent writes (`user_gesture_required`).
 */
export async function saveCredential(request, host = defaultNativeHost()) {
    return sendAuthedNativeMessage('save_credential', request, host);
}
// ============ Password generator (bridge protocol v5) ============
/**
 * Generate a password or passphrase via the bridge.
 * No vault write — pure generation. Requires authenticated session.
 */
export async function generatePassword(request, host = defaultNativeHost()) {
    return sendAuthedNativeMessage('generate_password', request, host);
}
//# sourceMappingURL=nativeBridge.js.map