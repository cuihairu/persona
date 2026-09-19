/**
 * nativeBridge 测试：sendNativeMessage 错误路径、配对状态机（hello/pairing/finalize/会话刷新）、
 * 以及 HMAC-SHA256 签名 —— 用 node:crypto 的 createHmac 独立复算签名串，
 * 验证 canonical JSON 的键排序（与 cli bridge.rs 的 Rust 实现对齐）。
 */
import { createHmac, webcrypto } from 'node:crypto';
import { TextEncoder as NodeTextEncoder } from 'node:util';
import {
    sendNativeMessage,
    hello,
    getStatus,
    requestPairingCode,
    finalizePairing,
    getSuggestions,
    passkeyCreate,
    getPairingState,
    type NativeBridgeResponse
} from './nativeBridge';

const PAIRING_KEY = '0123456789abcdef';
const PAIRING_KEY_B64 = Buffer.from(PAIRING_KEY, 'utf8').toString('base64url');
const PAIRING_STORAGE_KEY = 'persona_native_pairing_v1';

interface NativeCall {
    host: string;
    message: Record<string, any>;
}

/** chrome.runtime（native messaging）+ chrome.storage.local 的最小内存实现 */
function installChromeBridgeMock() {
    const data = new Map<string, unknown>();
    const calls: NativeCall[] = [];
    let responder: ((call: NativeCall) => unknown) | null = null;
    let lastErrorMessage: string | null = null;
    let syncThrow: Error | null = null;

    (globalThis as any).chrome = {
        runtime: {
            id: 'ext-id-123',
            getManifest: () => ({ version: '0.1.0' }),
            sendNativeMessage: (
                host: string,
                message: Record<string, any>,
                cb: (response: any) => void
            ) => {
                if (syncThrow) throw syncThrow;
                const call = { host, message };
                calls.push(call);
                let response: unknown;
                try {
                    response = responder ? responder(call) : { ok: true, payload: {} };
                } catch (error) {
                    response = { ok: false, error: error instanceof Error ? error.message : String(error) };
                }
                Promise.resolve(response).then((resolved) => {
                    if (lastErrorMessage) {
                        (globalThis as any).chrome.runtime.lastError = { message: lastErrorMessage };
                    }
                    cb(resolved);
                    delete (globalThis as any).chrome.runtime.lastError;
                });
            }
        },
        storage: {
            local: {
                get: (keys: unknown, cb: (items: Record<string, unknown>) => void) => {
                    const key = keys as string;
                    setTimeout(() => cb(data.has(key) ? { [key]: data.get(key) } : {}), 0);
                },
                set: (items: Record<string, unknown>, cb?: () => void) => {
                    for (const [key, value] of Object.entries(items)) data.set(key, value);
                    setTimeout(() => cb?.(), 0);
                }
            }
        }
    };

    return {
        calls,
        setResponder: (fn: ((call: NativeCall) => unknown) | null) => {
            responder = fn;
        },
        failNextWithLastError: (message: string) => {
            lastErrorMessage = message;
        },
        throwNextSync: (error: Error) => {
            syncThrow = error;
        },
        seedPairing: async (sessionId: string, expiresAtMs: number) => {
            data.set(PAIRING_STORAGE_KEY, {
                clientInstanceId: 'cid-1',
                pairingKeyB64: PAIRING_KEY_B64,
                sessionId,
                sessionExpiresAtMs: expiresAtMs
            });
        },
        stored: (key: string) => data.get(key),
        teardown: () => {
            delete (globalThis as any).chrome;
        }
    };
}

let mock: ReturnType<typeof installChromeBridgeMock>;

beforeAll(() => {
    // jsdom 的 crypto 没有 subtle，换 Node 的 webcrypto（含 randomUUID）；TextEncoder 同理补齐
    Object.defineProperty(globalThis, 'crypto', {
        value: webcrypto,
        configurable: true
    });
    if (typeof globalThis.TextEncoder === 'undefined') {
        Object.defineProperty(globalThis, 'TextEncoder', {
            value: NodeTextEncoder,
            configurable: true,
            writable: true
        });
    }
});

beforeEach(() => {
    mock = installChromeBridgeMock();
});

afterEach(() => {
    mock.teardown();
});

/** 用独立实现复算签名：签名串 kind\nrequest_id\npayload\nsession_id\nts_ms\nnonce */
function expectedSignature(kind: string, requestId: string, payloadJson: string, sessionId: string, tsMs: number, nonce: string): string {
    const signingInput = [kind, requestId, payloadJson, sessionId, String(tsMs), nonce].join('\n');
    return createHmac('sha256', Buffer.from(PAIRING_KEY, 'utf8'))
        .update(signingInput, 'utf8')
        .digest('base64url');
}

function authedCall(kind: string): NativeCall {
    const call = mock.calls.find((c) => c.message.type === kind);
    if (!call) throw new Error(`expected a ${kind} native call, got: ${mock.calls.map((c) => c.message.type).join(', ')}`);
    return call;
}

describe('sendNativeMessage', () => {
    it('resolves the raw response on the default host', async () => {
        mock.setResponder(() => ({ ok: true, payload: { locked: true } }));
        const response = await sendNativeMessage<{ locked: boolean }>({
            type: 'status',
            request_id: 'r1',
            payload: {}
        });
        expect(response).toEqual({ ok: true, payload: { locked: true } });
        expect(mock.calls[0].host).toBe('com.persona.native');
    });

    it('passes a custom host through', async () => {
        await sendNativeMessage({ type: 'status', request_id: 'r1', payload: {} }, 'com.persona.dev');
        expect(mock.calls[0].host).toBe('com.persona.dev');
    });

    it('surfaces chrome.runtime.lastError as a failed response', async () => {
        mock.failNextWithLastError('Native host has exited');
        const response: NativeBridgeResponse = await sendNativeMessage({
            type: 'status',
            request_id: 'r1',
            payload: {}
        });
        expect(response.ok).toBe(false);
        expect(response.error).toBe('Native host has exited');
    });

    it('surfaces synchronous send failures', async () => {
        mock.throwNextSync(new Error('Access to the native host denied'));
        const response = await sendNativeMessage({ type: 'status', request_id: 'r1', payload: {} });
        expect(response.ok).toBe(false);
        expect(response.error).toBe('Access to the native host denied');
    });
});

describe('pairing handshake', () => {
    it('hello sends the protocol v2 payload and persists clientInstanceId', async () => {
        mock.setResponder(() => ({
            ok: true,
            payload: { server_version: '2.0.1', capabilities: ['autofill'], pairing_required: true }
        }));

        const response = await hello();

        expect(response.ok).toBe(true);
        const call = mock.calls[0];
        expect(call.message.type).toBe('hello');
        expect(call.message.payload.protocol_version).toBe(2);
        expect(call.message.payload.extension_id).toBe('ext-id-123');
        expect(call.message.payload.extension_version).toBe('0.1.0');
        const state = await getPairingState();
        expect(call.message.payload.client_instance_id).toBe(state.clientInstanceId);
        // 响应无 session_id → 不得落盘
        expect(state.sessionId).toBeUndefined();
    });

    it('hello with a session id persists it for later signed requests', async () => {
        mock.setResponder(() => ({
            ok: true,
            payload: { session_id: 'sess-hello', session_expires_at_ms: 12345 }
        }));

        await hello();

        const state = await getPairingState();
        expect(state.sessionId).toBe('sess-hello');
        expect(state.sessionExpiresAtMs).toBe(12345);
    });

    it('requestPairingCode stores the code and expiry', async () => {
        mock.setResponder(() => ({
            ok: true,
            payload: { code: 'ABC-123', expires_at_ms: 999, approval_command: 'persona pair approve ABC-123' }
        }));

        const response = await requestPairingCode();

        expect(response.ok).toBe(true);
        const state = await getPairingState();
        expect(state.lastPairingCode).toBe('ABC-123');
        expect(state.lastPairingExpiresAtMs).toBe(999);
    });

    it('finalizePairing stores the pairing key + session and clears the code', async () => {
        mock.setResponder(() => ({
            ok: true,
            payload: {
                paired: true,
                pairing_key_b64: PAIRING_KEY_B64,
                session_id: 'sess-final',
                session_expires_at_ms: 4242
            }
        }));

        const response = await finalizePairing('ABC-123');

        expect(response.ok).toBe(true);
        const call = mock.calls[0];
        expect(call.message.type).toBe('pairing_finalize');
        expect(call.message.payload.code).toBe('ABC-123');
        const state = await getPairingState();
        expect(state.pairingKeyB64).toBe(PAIRING_KEY_B64);
        expect(state.sessionId).toBe('sess-final');
        expect(state.sessionExpiresAtMs).toBe(4242);
        expect(state.lastPairingCode).toBeUndefined();
        expect(state.lastPairingExpiresAtMs).toBeUndefined();
    });
});

describe('authed requests', () => {
    it('returns pairing_required without any native round-trip when unpaired', async () => {
        const response = await getSuggestions('https://example.com');
        expect(response).toEqual({ ok: false, error: 'pairing_required' });
        expect(mock.calls).toHaveLength(0);
    });

    it('signs requests over canonical JSON verifiable with an independent HMAC', async () => {
        await mock.seedPairing('sess-7', Date.now() + 3_600_000);

        const response = await getSuggestions('https://example.com');

        expect(response.ok).toBe(true);
        expect(mock.calls).toHaveLength(1); // 会话有效 → 不触发 hello
        const call = authedCall('get_suggestions');
        expect(call.message.payload).toEqual({ origin: 'https://example.com', form_type: 'login' });

        const auth = call.message.auth;
        expect(auth.session_id).toBe('sess-7');
        expect(auth.signature).toBe(
            expectedSignature(
                'get_suggestions',
                call.message.request_id,
                // canonical：键已按字典序排序（form_type < origin）
                JSON.stringify({ form_type: 'login', origin: 'https://example.com' }),
                'sess-7',
                auth.ts_ms,
                auth.nonce
            )
        );
    });

    it('canonicalizes nested payload keys recursively before signing', async () => {
        await mock.seedPairing('sess-7', Date.now() + 3_600_000);

        await passkeyCreate({
            origin: 'https://example.com',
            user_gesture: true,
            client_data_json_b64: 'x',
            request_json: { z: 1, a: { y: 2, b: 3 } }
        });

        const call = authedCall('passkey_create');
        // 手写 canonical 串：顶层 c<o<r<u，request_json 内 a<z，a 内 b<y
        const canonical =
            '{"client_data_json_b64":"x","origin":"https://example.com","request_json":{"a":{"b":3,"y":2},"z":1},"user_gesture":true}';
        const auth = call.message.auth;
        expect(auth.signature).toBe(
            expectedSignature('passkey_create', call.message.request_id, canonical, 'sess-7', auth.ts_ms, auth.nonce)
        );
    });

    it('refreshes an expired session via hello before signing', async () => {
        await mock.seedPairing('sess-old', Date.now() - 1_000);
        mock.setResponder((call) => {
            if (call.message.type === 'hello') {
                return {
                    ok: true,
                    payload: { session_id: 'sess-new', session_expires_at_ms: Date.now() + 3_600_000 }
                };
            }
            return { ok: true, payload: {} };
        });

        await getSuggestions('https://example.com');

        expect(mock.calls.map((c) => c.message.type)).toEqual(['hello', 'get_suggestions']);
        expect(authedCall('get_suggestions').message.auth.session_id).toBe('sess-new');
        expect((await getPairingState()).sessionId).toBe('sess-new');
    });

    it('getStatus stays unsigned (no auth block) even when paired', async () => {
        await mock.seedPairing('sess-7', Date.now() + 3_600_000);

        await getStatus();

        expect(mock.calls).toHaveLength(1);
        expect(mock.calls[0].message.type).toBe('status');
        expect(mock.calls[0].message.auth).toBeUndefined();
    });
});
