/**
 * 云端同步数据面（M5 批1，桥协议 v6）——扩展经 `sync_connect` 从本地桥取
 * (server_url, token, device_id, group key) 后，**HTTP 直连** server 的
 * `/api/v1/sync/oplog` 拉取并解密云端保险库：数据面出 native messaging 桥。
 *
 * 密码学口径与 core 对齐（零知识不变式）：
 * - 两级 AES-256-GCM（`EncryptionService` 同格式）：`nonce(12B) ‖ ct‖tag`；
 *   group key 拆 wrapped_item_key，item key 拆 payload.ciphertext。
 * - payload 明文 = bincode(SyncItemSnapshot)（bincode 1.3 默认配置：
 *   little-endian 定宽整数、u64 长度前缀、枚举 u32 变体索引、Option u8 tag）。
 *   本模块解码到元数据段（name/username/url/type）为止——完整解析与
 *   Rust 侧锚定测试双向校验（fixture 见 __fixtures__/sync_item_fixture.json）。
 * - LWW 全序（DR-4）：lamport 降序平手 device_id 字典序；真冲突 =
 *   同 item、lamport 相等、device_id 不同（保双版本待裁决）。
 *
 * 材料存放纪律：token 与 group key 只进 `chrome.storage.session`（内存区）；
 * 拉到的密文 op 缓存进 `chrome.storage.local`（离线兜底的本钱，本就公开
 * 于服务器，多一份副本不加深泄露面）。
 */

import { syncConnect, type SyncConnectPayload } from './nativeBridge';

// ---- wire 类型（与 core/src/sync/remote.rs 的 WireOp/WirePayload 对齐）----

export interface WirePayload {
    ciphertext: string;
    wrapped_item_key: string;
}

export interface WireOp {
    op_id: string;
    item_id: string;
    kind: string;
    op: 'put' | 'delete';
    lamport: number;
    device_id: string;
    /** 服务器原样转发的 rfc3339，仅展示。 */
    timestamp?: string | null;
    payload?: WirePayload | null;
}

export interface PullResponse {
    ops: WireOp[];
    next_cursor?: string | null;
}

/** 桥 sync_connect 发放的连接参数（session-only）。 */
export interface CloudConn {
    serverUrl: string;
    token: string;
    deviceId: string;
    deviceName: string;
    groupKeyHex: string;
}

/** SyncItemSnapshot 元数据段（扩展展示所需；password 等敏感字段不在此层）。 */
export interface SnapshotMeta {
    identity_id: string;
    name: string;
    credential_type: string;
    security_level: string;
    url: string | null;
    username: string | null;
    is_favorite: boolean;
    is_active: boolean;
}

export interface CloudItemView {
    item_id: string;
    kind: string;
    /** LWW 胜者（put 或 tombstone）。 */
    primary: WireOp;
    /** 真冲突副本（同 lamport 并发双版本，待裁决）。 */
    conflicts: WireOp[];
}

export interface CloudPullResult {
    ops: WireOp[];
    next_cursor: string | null;
    fetched_pages: number;
}

const OPLOG_PAGE_LIMIT = 500;
const OPLOG_MAX_PAGES = 40;

export const CLOUD_SESSION_KEY = 'persona_cloud_conn_v1';
export const CLOUD_CACHE_KEY = 'persona_cloud_ops_v1';

// ---- base64 / hex 工具 ----

export function hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
        throw new Error('invalid_hex');
    }
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

/** standard base64（core 的 B64 = general purpose STANDARD，非 url-safe）。 */
export function b64ToBytes(b64: string): Uint8Array {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

// ---- AES-256-GCM 两级拆封 ----

async function aesGcmDecrypt(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    if (data.length < 12 + 16) {
        // nonce(12) + tag(16) 都缺就谈不上解密
        throw new Error('ciphertext_too_short');
    }
    const key = await crypto.subtle.importKey(
        'raw',
        keyBytes as unknown as BufferSource,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );
    try {
        const plain = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: data.subarray(0, 12) as unknown as BufferSource },
            key,
            data.subarray(12) as unknown as BufferSource
        );
        return new Uint8Array(plain);
    } catch {
        // key 不对 / 篡改 —— 与 core 同口径 fail-closed，不区分成因
        throw new Error('decryption_failed');
    }
}

/** group key 拆 wrapped_item_key（`wrap_item_key_with_group` 的逆）。 */
export async function unwrapItemKey(
    wrappedItemKeyB64: string,
    groupKeyHex: string
): Promise<Uint8Array> {
    const itemKey = await aesGcmDecrypt(hexToBytes(groupKeyHex), b64ToBytes(wrappedItemKeyB64));
    if (itemKey.length !== 32) throw new Error('bad_item_key_length');
    return itemKey;
}

/** 拆 payload：group key → item key → bincode 快照明文。 */
export async function openPayload(
    payload: WirePayload,
    groupKeyHex: string
): Promise<Uint8Array> {
    const itemKey = await unwrapItemKey(payload.wrapped_item_key, groupKeyHex);
    return aesGcmDecrypt(itemKey, b64ToBytes(payload.ciphertext));
}

// ---- bincode 解码（SyncItemSnapshot 元数据段）----

class BincodeReader {
    private buf: Uint8Array;
    private view: DataView;
    private offset = 0;

    constructor(buf: Uint8Array) {
        this.buf = buf;
        this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    }

    u8(): number {
        if (this.offset + 1 > this.buf.length) throw new Error('bincode_eof');
        return this.view.getUint8(this.offset++);
    }

    bool(): boolean {
        const raw = this.u8();
        if (raw > 1) throw new Error('bincode_bad_bool');
        return raw === 1;
    }

    u32(): number {
        if (this.offset + 4 > this.buf.length) throw new Error('bincode_eof');
        const v = this.view.getUint32(this.offset, true);
        this.offset += 4;
        return v;
    }

    /** u64 长度前缀；JS 安全整数范围内（长度字段超 2^53 直接拒）。 */
    u64Length(): number {
        if (this.offset + 8 > this.buf.length) throw new Error('bincode_eof');
        const lo = this.view.getUint32(this.offset, true);
        const hi = this.view.getUint32(this.offset + 4, true);
        this.offset += 8;
        if (hi > 0x1fffff) throw new Error('bincode_length_overflow');
        return hi * 0x100000000 + lo;
    }

    bytes(n: number): Uint8Array {
        if (this.offset + n > this.buf.length) throw new Error('bincode_eof');
        const out = this.buf.subarray(this.offset, this.offset + n);
        this.offset += n;
        return out;
    }

    string(): string {
        const len = this.u64Length();
        const raw = this.bytes(len);
        return new TextDecoder('utf-8', { fatal: true }).decode(raw);
    }

    optionString(): string | null {
        return this.u8() === 1 ? this.string() : null;
    }

    stringVec(): string[] {
        const n = this.u64Length();
        const out: string[] = [];
        for (let i = 0; i < n; i++) out.push(this.string());
        return out;
    }

    stringMap(): Record<string, string> {
        const n = this.u64Length();
        const out: Record<string, string> = {};
        for (let i = 0; i < n; i++) {
            const k = this.string();
            out[k] = this.string();
        }
        return out;
    }

    /** Uuid 在非 human-readable 序列化下走 serialize_bytes → bincode 还带 u64 长度前缀。 */
    uuidString(): string {
        const len = this.u64Length();
        if (len !== 16) throw new Error('bincode_bad_uuid_length');
        const b = this.bytes(16);
        const hex = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    }
}

/** 与 core/src/models/credential.rs CredentialType 变体序一致（索引不可变）。 */
const CREDENTIAL_TYPE_NAMES = [
    'Password',
    'CryptoWallet',
    'SshKey',
    'ApiKey',
    'BankCard',
    'GameAccount',
    'ServerConfig',
    'Certificate',
    'TwoFactor',
    'SecureNote',
    'Identity',
    'SoftwareLicense',
    'Custom',
];

const SECURITY_LEVEL_NAMES = ['Critical', 'High', 'Medium', 'Low'];

/**
 * 解码 `bincode(SyncItemSnapshot)` 到元数据段为止（解到 `data` 枚举标签
 * 后停止——完整 CredentialData 解析留在写路径批次，这里只做只读展示）。
 * 任何字段越界/非法值一律抛错，调用方按条目级容错跳过（与 core 的
 * 「条目级损坏跳过」口径一致）。
 */
export function decodeSyncItemSnapshot(bytes: Uint8Array): SnapshotMeta {
    const r = new BincodeReader(bytes);
    const identity_id = r.uuidString();
    const name = r.string();

    const typeIdx = r.u32();
    let credential_type = CREDENTIAL_TYPE_NAMES[typeIdx];
    if (credential_type === undefined) throw new Error('bincode_bad_credential_type');
    // Rust Display 对 Custom 输出裸内部字符串（不带 Custom(...) 包裹）
    if (credential_type === 'Custom') credential_type = r.string();

    const levelIdx = r.u32();
    const security_level = SECURITY_LEVEL_NAMES[levelIdx];
    if (security_level === undefined) throw new Error('bincode_bad_security_level');

    const url = r.optionString();
    const username = r.optionString();
    const notes = r.optionString();
    r.stringVec();
    r.stringMap();
    const is_favorite = r.bool();
    const is_active = r.bool();
    r.u32(); // CredentialData 变体标签（读出即校验，payload 不在本层解析）

    return {
        identity_id,
        name,
        credential_type,
        security_level,
        url,
        username,
        is_favorite,
        is_active,
    };
}

// ---- LWW 视图合并（core oplog::compare_ops 同序）----

function compareOpsAsc(a: WireOp, b: WireOp): number {
    if (a.lamport !== b.lamport) return a.lamport - b.lamport;
    return a.device_id < b.device_id ? -1 : a.device_id > b.device_id ? 1 : 0;
}

/** 按 LWW 全序收拢：primary = lamport 最大（平手 device_id 最大）；
 * 真冲突副本 = 与 primary 同 lamport、device_id 不同的并发版本。 */
export function buildItemViews(ops: WireOp[]): CloudItemView[] {
    const byItem = new Map<string, WireOp[]>();
    for (const op of ops) {
        const list = byItem.get(op.item_id);
        if (list) list.push(op);
        else byItem.set(op.item_id, [op]);
    }

    const views: CloudItemView[] = [];
    for (const [item_id, list] of byItem) {
        const sorted = [...list].sort(compareOpsAsc);
        const primary = sorted[sorted.length - 1];
        const conflicts = sorted.filter(
            (op) =>
                op !== primary &&
                op.lamport === primary.lamport &&
                op.device_id !== primary.device_id
        );
        views.push({ item_id, kind: primary.kind, primary, conflicts });
    }
    return views;
}

// ---- 连接参数：桥引导 + session-only 存取 ----

export function connFromSyncConnect(payload: SyncConnectPayload): CloudConn {
    if (!payload.server_url || !payload.token || !payload.group_key_hex) {
        throw new Error('incomplete_sync_connect_payload');
    }
    return {
        serverUrl: payload.server_url.replace(/\/+$/, ''),
        token: payload.token,
        deviceId: payload.device_id,
        deviceName: payload.device_name,
        groupKeyHex: payload.group_key_hex,
    };
}

/** 走桥取参数（popup 显式点击触发 = user_gesture）。 */
export async function connectViaBridge(): Promise<CloudConn> {
    const resp = await syncConnect();
    if (!resp.ok || !resp.payload) {
        throw new Error(resp.error ?? 'sync_connect_failed');
    }
    return connFromSyncConnect(resp.payload);
}

export async function saveCloudConn(conn: CloudConn): Promise<void> {
    await chrome.storage.session.set({ [CLOUD_SESSION_KEY]: conn });
}

export async function loadCloudConn(): Promise<CloudConn | undefined> {
    const got = await chrome.storage.session.get(CLOUD_SESSION_KEY);
    return got[CLOUD_SESSION_KEY] as CloudConn | undefined;
}

// ---- HTTP 直连拉取（分页翻 cursor）----

export async function pullCloudOps(
    conn: CloudConn,
    since?: string | null,
    fetchImpl: typeof fetch = fetch
): Promise<CloudPullResult> {
    const ops: WireOp[] = [];
    let cursor: string | null | undefined = since ?? null;
    let pages = 0;

    for (;;) {
        if (pages >= OPLOG_MAX_PAGES) throw new Error('oplog_pull_too_many_pages');
        const url = new URL(`${conn.serverUrl}/api/v1/sync/oplog`);
        url.searchParams.set('limit', String(OPLOG_PAGE_LIMIT));
        if (cursor) url.searchParams.set('since', cursor);

        const resp = await fetchImpl(url.toString(), {
            headers: { Authorization: `Bearer ${conn.token}` },
        });
        if (!resp.ok) {
            let detail = '';
            try {
                const body = (await resp.json()) as { error?: { message?: string } };
                detail = body?.error?.message ? `: ${body.error.message}` : '';
            } catch {
                // 非 JSON 错误体：只报状态码
            }
            throw new Error(`oplog_pull_failed (HTTP ${resp.status})${detail}`);
        }
        const body = (await resp.json()) as PullResponse;
        ops.push(...(body.ops ?? []));
        pages += 1;
        cursor = body.next_cursor ?? null;
        if (!cursor) break;
    }

    return { ops, next_cursor: cursor, fetched_pages: pages };
}

// ---- 密文缓存（chrome.storage.local，离线兜底本钱）----

export interface CloudCache {
    server_url: string;
    ops: WireOp[];
    next_cursor: string | null;
    synced_at: number;
}

export async function saveCloudCache(cache: CloudCache): Promise<void> {
    await chrome.storage.local.set({ [CLOUD_CACHE_KEY]: cache });
}

export async function loadCloudCache(): Promise<CloudCache | undefined> {
    const got = await chrome.storage.local.get(CLOUD_CACHE_KEY);
    return got[CLOUD_CACHE_KEY] as CloudCache | undefined;
}

/**
 * 离线兜底判据（M5 批4a）：缓存存在、指向同一台 server、且真的有 op。
 * 换了服务器（server_url 不匹配）的旧缓存不能拿来渲染——group key 可能对不上。
 */
export function isUsableCache(
    cache: CloudCache | undefined,
    conn: CloudConn
): cache is CloudCache {
    return Boolean(
        cache && cache.server_url === conn.serverUrl && cache.ops.length > 0
    );
}

// ---- 展示层：拉取 + 逐条解密（条目级容错）----

export interface CloudListItem {
    item_id: string;
    kind: string;
    /** tombstone = 已删除（不展示内容）。 */
    deleted: boolean;
    lamport: number;
    device_id: string;
    conflict_count: number;
    meta: SnapshotMeta | null;
    /** payload 解密/解码失败（条目级容错，如实展示而非吞掉）。 */
    decrypt_error?: string;
}

/** 把 LWW 视图解成展示列表：put 解密元数据，delete 如实标墓碑。 */
export async function decryptItemViews(
    views: CloudItemView[],
    groupKeyHex: string
): Promise<CloudListItem[]> {
    const items: CloudListItem[] = [];
    for (const view of views) {
        const base = {
            item_id: view.item_id,
            kind: view.kind,
            deleted: view.primary.op === 'delete',
            lamport: view.primary.lamport,
            device_id: view.primary.device_id,
            conflict_count: view.conflicts.length,
        };
        if (!view.primary.payload) {
            items.push({ ...base, meta: null });
            continue;
        }
        try {
            const plaintext = await openPayload(view.primary.payload, groupKeyHex);
            items.push({ ...base, meta: decodeSyncItemSnapshot(plaintext) });
        } catch (error) {
            items.push({
                ...base,
                meta: null,
                decrypt_error: error instanceof Error ? error.message : String(error),
            });
        }
    }
    return items;
}

// ---- 冲突裁决展示（M5 批4b）----

/** 冲突副本的展示视图：解出名字供「保留哪个版本」决策，解不出如实标注。 */
export interface ConflictCopyView {
    op_id: string;
    device_id: string;
    lamport: number;
    deleted: boolean;
    meta: SnapshotMeta | null;
    decrypt_error?: string;
}

/**
 * 解密一个条目的并发冲突副本（`sync_resolve_conflict` 的 adopt_op_id 就从
 * 这里的 op_id 里选）。与 decryptItemViews 同条目级容错口径。
 */
export async function conflictCopyViews(
    view: CloudItemView,
    groupKeyHex: string
): Promise<ConflictCopyView[]> {
    const copies: ConflictCopyView[] = [];
    for (const copy of view.conflicts) {
        const base = {
            op_id: copy.op_id,
            device_id: copy.device_id,
            lamport: copy.lamport,
            deleted: copy.op === 'delete',
        };
        if (!copy.payload) {
            copies.push({ ...base, meta: null });
            continue;
        }
        try {
            const plaintext = await openPayload(copy.payload, groupKeyHex);
            copies.push({ ...base, meta: decodeSyncItemSnapshot(plaintext) });
        } catch (error) {
            copies.push({
                ...base,
                meta: null,
                decrypt_error: error instanceof Error ? error.message : String(error),
            });
        }
    }
    return copies;
}
