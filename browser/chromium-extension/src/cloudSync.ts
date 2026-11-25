/**
 * Cloud sync data plane (M5 batch 1, bridge protocol v6) — after the extension gets
 * (server_url, token, device_id, group key) from the local bridge via `sync_connect`,
 * it connects **directly over HTTP** to the server's
 * `/api/v1/sync/oplog` to pull and decrypt the cloud vault: the data plane bypasses the native messaging bridge.
 *
 * Crypto conventions match core (zero-knowledge invariant):
 * - Two-level AES-256-GCM (same format as `EncryptionService`): `nonce(12B) ‖ ct‖tag`;
 *   group key unwraps wrapped_item_key, item key unwraps payload.ciphertext.
 * - Payload plaintext = bincode(SyncItemSnapshot) (bincode 1.3 default config:
 *   little-endian fixed-width integers, u64 length prefixes, enum u32 variant index, Option u8 tag).
 *   This module only decodes the metadata segment (name/username/url/type) — full parsing is
 *   cross-checked against the Rust-side anchored tests (fixture at __fixtures__/sync_item_fixture.json).
 * - LWW total order (DR-4): descending lamport, ties broken by device_id lexicographic order; a true conflict =
 *   same item, equal lamport, different device_id (both versions kept pending resolution).
 *
 * Material storage discipline: token and group key go only into `chrome.storage.session` (memory area);
 * pulled ciphertext ops are cached in `chrome.storage.local` (the offline-fallback stake, already public
 * to the server, so one more copy does not widen the exposure surface).
 */

import { syncConnect, type SyncConnectPayload } from './nativeBridge.js';

// ---- wire types (aligned with WireOp/WirePayload in core/src/sync/remote.rs) ----

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
    /** rfc3339 string forwarded verbatim by the server, display only. */
    timestamp?: string | null;
    payload?: WirePayload | null;
}

export interface PullResponse {
    ops: WireOp[];
    next_cursor?: string | null;
}

/** Connection parameters issued by the bridge's sync_connect (session-only). */
export interface CloudConn {
    serverUrl: string;
    token: string;
    deviceId: string;
    deviceName: string;
    groupKeyHex: string;
}

/** SyncItemSnapshot metadata segment (what the extension displays; sensitive fields such as password live elsewhere). */
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
    /** LWW winner (put or tombstone). */
    primary: WireOp;
    /** Genuine conflict copies (concurrent versions at the same lamport, awaiting resolution). */
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

// ---- base64 / hex utilities ----

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

/** standard base64 (core's B64 = general purpose STANDARD, not url-safe). */
export function b64ToBytes(b64: string): Uint8Array {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

// ---- AES-256-GCM two-level unwrapping ----

async function aesGcmDecrypt(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    if (data.length < 12 + 16) {
        // if both nonce(12) and tag(16) are missing there is nothing to decrypt
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
        // wrong key / tampering — fail-closed, same rule as core, cause not distinguished
        throw new Error('decryption_failed');
    }
}

/** Unwrap wrapped_item_key with the group key (inverse of `wrap_item_key_with_group`). */
export async function unwrapItemKey(
    wrappedItemKeyB64: string,
    groupKeyHex: string
): Promise<Uint8Array> {
    const itemKey = await aesGcmDecrypt(hexToBytes(groupKeyHex), b64ToBytes(wrappedItemKeyB64));
    if (itemKey.length !== 32) throw new Error('bad_item_key_length');
    return itemKey;
}

/** Open a payload: group key -> item key -> bincode snapshot plaintext. */
export async function openPayload(
    payload: WirePayload,
    groupKeyHex: string
): Promise<Uint8Array> {
    const itemKey = await unwrapItemKey(payload.wrapped_item_key, groupKeyHex);
    return aesGcmDecrypt(itemKey, b64ToBytes(payload.ciphertext));
}

// ---- bincode decoding (SyncItemSnapshot metadata segment) ----

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

    /** u64 length prefix; kept within JS safe integer range (length fields over 2^53 are rejected outright). */
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

    /** Uuid goes through serialize_bytes under non-human-readable serialization, so bincode still carries a u64 length prefix. */
    uuidString(): string {
        const len = this.u64Length();
        if (len !== 16) throw new Error('bincode_bad_uuid_length');
        const b = this.bytes(16);
        const hex = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    }
}

/** Matches the variant order of CredentialType in core/src/models/credential.rs (indices are immutable). */
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
 * Decode `bincode(SyncItemSnapshot)` up to the metadata segment (stopping right after the
 * `data` enum tag — full CredentialData parsing belongs to the write-path batch, this is read-only display).
 * Any out-of-range or invalid field throws; callers skip at item level for fault tolerance (same
 * "skip corrupt item" rule as core).
 */
export function decodeSyncItemSnapshot(bytes: Uint8Array): SnapshotMeta {
    const r = new BincodeReader(bytes);
    const identity_id = r.uuidString();
    const name = r.string();

    const typeIdx = r.u32();
    let credential_type = CREDENTIAL_TYPE_NAMES[typeIdx];
    if (credential_type === undefined) throw new Error('bincode_bad_credential_type');
    // Rust Display prints Custom as the bare inner string (no Custom(...) wrapper)
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
    r.u32(); // CredentialData variant tag (read to validate; payload is not parsed at this layer)

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

// ---- LWW view merging (same ordering as core oplog::compare_ops) ----

function compareOpsAsc(a: WireOp, b: WireOp): number {
    if (a.lamport !== b.lamport) return a.lamport - b.lamport;
    return a.device_id < b.device_id ? -1 : a.device_id > b.device_id ? 1 : 0;
}

/** Collapse by LWW total order: primary = highest lamport (ties: highest device_id);
 * genuine conflict copies = concurrent versions sharing primary's lamport with a different device_id. */
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

// ---- connection parameters: bridge bootstrap + session-only storage ----

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

/** Fetch parameters over the bridge (triggered by an explicit popup click = user_gesture). */
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

// ---- direct HTTP pull (paged cursor flipping) ----

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
                // non-JSON error body: report the status code only
            }
            throw new Error(`oplog_pull_failed (HTTP ${resp.status})${detail}`);
        }
        // guard the success path against non-JSON bodies too: untrusted input, a parse failure
        // must become an explicit error (same discipline as the error body at :389), not a bare SyntaxError.
        let body: PullResponse;
        try {
            body = (await resp.json()) as PullResponse;
        } catch {
            throw new Error(`oplog_pull_failed (HTTP ${resp.status}): malformed JSON response`);
        }
        ops.push(...(body.ops ?? []));
        pages += 1;
        cursor = body.next_cursor ?? null;
        if (!cursor) break;
    }

    return { ops, next_cursor: cursor, fetched_pages: pages };
}

// ---- ciphertext cache (chrome.storage.local, the offline-fallback stake) ----

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
 * Offline-fallback eligibility (M5 batch 4a): a cache exists, points at the same server,
 * and actually contains ops. Stale caches from a different server (server_url mismatch) must
 * not be used for rendering — the group key may not line up.
 */
export function isUsableCache(
    cache: CloudCache | undefined,
    conn: CloudConn
): cache is CloudCache {
    return Boolean(
        cache && cache.server_url === conn.serverUrl && cache.ops.length > 0
    );
}

// ---- display layer: pull + per-item decryption (item-level fault tolerance) ----

export interface CloudListItem {
    item_id: string;
    kind: string;
    /** tombstone = deleted (no content displayed). */
    deleted: boolean;
    lamport: number;
    device_id: string;
    conflict_count: number;
    meta: SnapshotMeta | null;
    /** payload decryption/decoding failed (item-level fault tolerance: reported honestly rather than swallowed). */
    decrypt_error?: string;
}

/** Resolve LWW views into a display list: decrypt metadata for puts, mark tombstones for deletes. */
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

// ---- conflict resolution display (M5 batch 4b) ----

/** Display view for conflict copies: decrypt the name to back the "keep which version" decision, else report the failure honestly. */
export interface ConflictCopyView {
    op_id: string;
    device_id: string;
    lamport: number;
    deleted: boolean;
    meta: SnapshotMeta | null;
    decrypt_error?: string;
}

/**
 * Decrypt an item's concurrent conflict copies (`sync_resolve_conflict` picks its
 * adopt_op_id from the op_id values here). Same item-level fault tolerance as decryptItemViews.
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
