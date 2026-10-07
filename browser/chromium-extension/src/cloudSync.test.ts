/**
 * cloudSync 数据面测试（M5 批1）：
 * - 跨语言 fixture 锚定：__fixtures__/sync_item_fixture*.json 由 Rust 侧
 *   emit_sync_item_fixture 生成（cli 测试会读回校验双向一致），这里用同一份
 *   密文跑 WebCrypto 两级拆封 + bincode 解码，等价于对 Rust 加密/序列化做回放。
 * - LWW 视图合并（DR-4 全序）、HTTP 分页拉取、session/local 存取语义。
 * jsdom 的 crypto 没有 subtle —— 换 Node 的 webcrypto。
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { webcrypto } from 'node:crypto';

import {
    hexToBytes,
    b64ToBytes,
    unwrapItemKey,
    openPayload,
    decodeSyncItemSnapshot,
    buildItemViews,
    connFromSyncConnect,
    pullCloudOps,
    decryptItemViews,
    saveCloudConn,
    loadCloudConn,
    saveCloudCache,
    loadCloudCache,
    CLOUD_SESSION_KEY,
    CLOUD_CACHE_KEY,
    type WireOp,
    type CloudConn,
} from './cloudSync';

interface Fixture {
    ciphertext_b64: string;
    wrapped_item_key_b64: string;
    item_key_hex: string;
    group_key_hex: string;
    expected: {
        identity_id: string;
        name: string;
        credential_type: string;
        security_level: string;
        url: string | null;
        username: string | null;
        is_favorite: boolean;
        is_active: boolean;
    };
}

function loadFixture(name: string): Fixture {
    const path = join(__dirname, '__fixtures__', name);
    return JSON.parse(readFileSync(path, 'utf8')) as Fixture;
}

const RICH = loadFixture('sync_item_fixture.json');
const SPARSE = loadFixture('sync_item_fixture_sparse.json');

beforeAll(() => {
    // jsdom 没有 WebCrypto subtle —— 用 Node 的 webcrypto
    Object.defineProperty(globalThis, 'crypto', {
        value: webcrypto,
        configurable: true,
    });
    if (typeof globalThis.TextDecoder === 'undefined') {
        (globalThis as any).TextDecoder = (require('node:util').TextDecoder);
    }
});

afterAll(() => {
    delete (globalThis as any).crypto;
    delete (globalThis as any).chrome;
});

// ---- 工具函数 ----

describe('hex/base64 解码', () => {
    it('hexToBytes 还原字节序列', () => {
        expect(Array.from(hexToBytes('00ff10'))).toEqual([0, 255, 16]);
    });

    it('hexToBytes 拒绝奇数长度与非法字符', () => {
        expect(() => hexToBytes('abc')).toThrow('invalid_hex');
        expect(() => hexToBytes('zz')).toThrow('invalid_hex');
    });

    it('b64ToBytes 解 standard base64（core 的 B64 非 url-safe）', () => {
        expect(Array.from(b64ToBytes('AAEC'))).toEqual([0, 1, 2]);
    });
});

// ---- 跨语言 fixture：WebCrypto 回放 Rust 加密 ----

describe('跨语言 fixture（Rust 生成 → TS 拆封解码）', () => {
    it('RICH：group key 拆 item key → item key 拆快照 → 元数据全等', async () => {
        const itemKey = await unwrapItemKey(RICH.wrapped_item_key_b64, RICH.group_key_hex);
        expect(Buffer.from(itemKey).toString('hex')).toBe(RICH.item_key_hex);

        const plain = await openPayload(
            { ciphertext: RICH.ciphertext_b64, wrapped_item_key: RICH.wrapped_item_key_b64 },
            RICH.group_key_hex
        );
        expect(decodeSyncItemSnapshot(plain)).toEqual(RICH.expected);
    });

    it('SPARSE：Custom 变体输出裸内部字符串（Rust Display 口径），Option 空字段为 null', async () => {
        const plain = await openPayload(
            { ciphertext: SPARSE.ciphertext_b64, wrapped_item_key: SPARSE.wrapped_item_key_b64 },
            SPARSE.group_key_hex
        );
        const meta = decodeSyncItemSnapshot(plain);
        expect(meta).toEqual(SPARSE.expected);
        expect(meta.credential_type).toBe('内部工具'); // 不是 "Custom(内部工具)"
        expect(meta.url).toBeNull();
        expect(meta.username).toBeNull();
    });

    it('组密钥不对 → decryption_failed（fail-closed，不区分成因）', async () => {
        await expect(
            unwrapItemKey(RICH.wrapped_item_key_b64, '33'.repeat(32))
        ).rejects.toThrow('decryption_failed');
    });

    it('密文过短 → ciphertext_too_short', async () => {
        await expect(unwrapItemKey('AAAA', RICH.group_key_hex)).rejects.toThrow(
            'ciphertext_too_short'
        );
    });
});

// ---- LWW 视图合并（DR-4）----

function op(partial: Partial<WireOp> & Pick<WireOp, 'item_id'>): WireOp {
    return {
        op_id: `op-${partial.item_id}-${partial.lamport ?? 0}-${partial.device_id ?? 'd'}`,
        kind: 'credential',
        op: 'put',
        lamport: 1,
        device_id: 'device-a',
        timestamp: '2026-10-07T00:00:00Z',
        payload: null,
        ...partial,
    };
}

describe('buildItemViews（LWW 全序）', () => {
    it('同条目取 lamport 最大为 primary，低 lamport 不算冲突', () => {
        const views = buildItemViews([
            op({ item_id: 'i1', lamport: 1, device_id: 'device-a' }),
            op({ item_id: 'i1', lamport: 5, device_id: 'device-b' }),
        ]);
        expect(views).toHaveLength(1);
        expect(views[0].primary.lamport).toBe(5);
        expect(views[0].conflicts).toHaveLength(0);
    });

    it('lamport 平手 + device_id 不同 = 真冲突，device_id 字典序大者胜', () => {
        const views = buildItemViews([
            op({ item_id: 'i1', lamport: 7, device_id: 'device-a' }),
            op({ item_id: 'i1', lamport: 7, device_id: 'device-b' }),
        ]);
        expect(views[0].primary.device_id).toBe('device-b');
        expect(views[0].conflicts).toHaveLength(1);
        expect(views[0].conflicts[0].device_id).toBe('device-a');
    });

    it('不同条目各成视图；同 lamport 同 device 后写覆盖前写（非真冲突）', () => {
        const views = buildItemViews([
            op({ item_id: 'i1', lamport: 3, device_id: 'device-a' }),
            op({ item_id: 'i2', lamport: 3, device_id: 'device-a' }),
            op({ item_id: 'i1', lamport: 3, device_id: 'device-a', op_id: 'op-newer' }),
        ]);
        expect(views).toHaveLength(2);
        const i1 = views.find((v) => v.item_id === 'i1')!;
        expect(i1.primary.op_id).toBe('op-newer');
        expect(i1.conflicts).toHaveLength(0);
    });
});

// ---- 连接参数 ----

describe('connFromSyncConnect', () => {
    const payload = {
        server_url: 'https://sync.example.com/',
        token: 'tok',
        device_id: 'dev-1',
        device_name: 'laptop',
        group_key_hex: '22'.repeat(32),
    };

    it('去尾斜杠并保留全部字段', () => {
        expect(connFromSyncConnect(payload)).toEqual<CloudConn>({
            serverUrl: 'https://sync.example.com',
            token: 'tok',
            deviceId: 'dev-1',
            deviceName: 'laptop',
            groupKeyHex: '22'.repeat(32),
        });
    });

    it('缺 token/group key 直接抛（不半连）', () => {
        expect(() => connFromSyncConnect({ ...payload, token: '' })).toThrow(
            'incomplete_sync_connect_payload'
        );
        expect(() => connFromSyncConnect({ ...payload, group_key_hex: '' })).toThrow(
            'incomplete_sync_connect_payload'
        );
    });
});

// ---- HTTP 分页拉取 ----

describe('pullCloudOps', () => {
    const conn: CloudConn = {
        serverUrl: 'https://sync.example.com',
        token: 'tok',
        deviceId: 'dev-1',
        deviceName: 'laptop',
        groupKeyHex: '22'.repeat(32),
    };

    it('翻 cursor 直到 next_cursor 为空，Bearer 与 since 正确传递', async () => {
        const urls: string[] = [];
        const authHeaders: (string | undefined)[] = [];
        const pages = [
            { ops: [op({ item_id: 'i1' })], next_cursor: 'c1' },
            { ops: [op({ item_id: 'i2' })], next_cursor: null },
        ];
        let i = 0;
        const fetchImpl = jest.fn(async (url: string, init: RequestInit) => {
            urls.push(url);
            authHeaders.push((init.headers as Record<string, string>)?.Authorization);
            const body = pages[i++];
            return {
                ok: true,
                status: 200,
                json: async () => body,
            } as unknown as Response;
        }) as unknown as typeof fetch;

        const result = await pullCloudOps(conn, null, fetchImpl);
        expect(result.ops).toHaveLength(2);
        expect(result.fetched_pages).toBe(2);
        expect(result.next_cursor).toBeNull();

        const u0 = new URL(urls[0]);
        expect(u0.origin + u0.pathname).toBe('https://sync.example.com/api/v1/sync/oplog');
        expect(u0.searchParams.get('limit')).toBe('500');
        expect(u0.searchParams.get('since')).toBeNull();
        const u1 = new URL(urls[1]);
        expect(u1.searchParams.get('since')).toBe('c1');
        expect(authHeaders).toEqual(['Bearer tok', 'Bearer tok']);
    });

    it('HTTP 错误带状态码与服务端 error.message', async () => {
        const fetchImpl = jest.fn(async () =>
            ({
                ok: false,
                status: 401,
                json: async () => ({ error: { message: 'invalid token' } }),
            }) as unknown as Response
        ) as unknown as typeof fetch;

        await expect(pullCloudOps(conn, null, fetchImpl)).rejects.toThrow(
            'oplog_pull_failed (HTTP 401): invalid token'
        );
    });

    it('cursor 永不收敛 → oplog_pull_too_many_pages（不无限翻页）', async () => {
        const fetchImpl = jest.fn(async () =>
            ({
                ok: true,
                status: 200,
                json: async () => ({ ops: [], next_cursor: 'always-more' }),
            }) as unknown as Response
        ) as unknown as typeof fetch;

        await expect(pullCloudOps(conn, null, fetchImpl)).rejects.toThrow(
            'oplog_pull_too_many_pages'
        );
        expect(fetchImpl).toHaveBeenCalledTimes(40);
    });
});

// ---- session/local 存取 ----

describe('连接参数与密文缓存的存储语义', () => {
    let store: Record<string, unknown>;

    beforeEach(() => {
        store = {};
        (globalThis as any).chrome = {
            storage: {
                session: {
                    set: async (obj: Record<string, unknown>) => Object.assign(store, obj),
                    get: async (key: string) => ({ [key]: store[key] }),
                },
                local: {
                    set: async (obj: Record<string, unknown>) => Object.assign(store, obj),
                    get: async (key: string) => ({ [key]: store[key] }),
                },
            },
        };
    });

    afterEach(() => {
        delete (globalThis as any).chrome;
    });

    it('连接参数走 session 键，密文缓存走 local 键（材料纪律）', async () => {
        const conn: CloudConn = {
            serverUrl: 'https://sync.example.com',
            token: 'tok',
            deviceId: 'dev-1',
            deviceName: 'laptop',
            groupKeyHex: '22'.repeat(32),
        };
        await saveCloudConn(conn);
        expect(store[CLOUD_SESSION_KEY]).toBeDefined();
        expect(store[CLOUD_CACHE_KEY]).toBeUndefined();
        expect(await loadCloudConn()).toEqual(conn);

        const cache = {
            server_url: conn.serverUrl,
            ops: [op({ item_id: 'i1' })],
            next_cursor: null,
            synced_at: 123,
        };
        await saveCloudCache(cache);
        expect(store[CLOUD_CACHE_KEY]).toBeDefined();
        expect(await loadCloudCache()).toEqual(cache);
    });

    it('空存储 → undefined（不抛）', async () => {
        expect(await loadCloudConn()).toBeUndefined();
        expect(await loadCloudCache()).toBeUndefined();
    });
});

// ---- 展示层解密（条目级容错）----

describe('decryptItemViews', () => {
    it('put 解密出元数据；delete 标墓碑；坏密文条目级容错', async () => {
        const views = [
            {
                item_id: 'i1',
                kind: 'credential',
                primary: op({
                    item_id: 'i1',
                    payload: {
                        ciphertext: RICH.ciphertext_b64,
                        wrapped_item_key: RICH.wrapped_item_key_b64,
                    },
                }),
                conflicts: [],
            },
            {
                item_id: 'i2',
                kind: 'credential',
                primary: op({ item_id: 'i2', op: 'delete', payload: null }),
                conflicts: [],
            },
            {
                item_id: 'i3',
                kind: 'credential',
                primary: op({
                    item_id: 'i3',
                    payload: {
                        ciphertext: Buffer.from('garbage-ciphertext-garbage-ciphertext!').toString('base64'),
                        wrapped_item_key: RICH.wrapped_item_key_b64,
                    },
                }),
                conflicts: [],
            },
        ];

        const items = await decryptItemViews(views, RICH.group_key_hex);
        expect(items).toHaveLength(3);

        expect(items[0].meta?.name).toBe(RICH.expected.name);
        expect(items[0].deleted).toBe(false);
        expect(items[0].decrypt_error).toBeUndefined();

        expect(items[1].deleted).toBe(true);
        expect(items[1].meta).toBeNull();

        expect(items[2].meta).toBeNull();
        expect(items[2].decrypt_error).toBe('decryption_failed');
    });
});
