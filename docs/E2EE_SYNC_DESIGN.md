# E2EE Sync Design (Stage 0)

> [English](E2EE_SYNC_DESIGN.md) | [中文](E2EE_SYNC_DESIGN.zh.md)

> Status: **Design doc; stages 1–4 have all landed (2026-09, per-stage status in the §11 table)**.
> This is the kickoff document for TODO "step 3" (Connect endpoint + E2EE sync + SRP device
> auth): it settles the four design decisions that had to be decided up front, and gives the
> implementation-stage mapping plus a threat-model registration skeleton. The currently active
> follow-on batch is sync group mode ([`sync-group-mode.md`](./sync-group-mode.md)) — S2
> converges the existing snapshot + LWW oplog pipeline onto an instruction stream
> (op_id idempotency + cursor resumption).
>
> Related docs: [`ROADMAP.md`](./ROADMAP.md) Milestone 6, [`REMOTE_AUTH.md`](./REMOTE_AUTH.md)
> (the existing SRP abstraction and mock), [`STORAGE_AND_SYNC.md`](./STORAGE_AND_SYNC.md)
> (the current state from the user's perspective), [`THREAT_MODEL.md`](./THREAT_MODEL.md)
> (the honest-boundary precedent set by the "backup custody endpoint" and "Travel Mode").

## 1. Goals and Non-Goals

**Goals**

1. Credential-level incremental sync of **the same Persona workspace** across multiple
   devices; the server only ever sees ciphertext and minimal metadata.
2. Sync layer **decoupled from the master password**: changing the master password is a
   purely local operation that triggers no fleet-wide re-wrapping.
3. Explicit join/removal flows for devices; the blast radius of removal is honestly
   registered (see §9).
4. Reuse of existing assets: the per-item key envelope structure, the server skeleton,
   the `RemoteAuthProvider` abstraction, the fail-closed convention, and the backup
   custody chain (without disrupting it).

**Non-goals (explicitly out of scope for the first phase)**

- **CRDT / field-level merge**: a credential is an atomic whole; conflicts keep both
   versions for the user to adjudicate (§7).
- **Tampering and rollback protection against a malicious/compromised server**: same
   boundary as backup custody — the client does no freshness validation and makes no
   claim of defending against the server operator.
- **Device-private-key signing of the oplog** (against a server forging history):
   long-term item, see §12.
- **Attachment blob sync**: v1 syncs in-database rows only; attachments go through the
   existing backup channel (whose v1 boundary is the same).
- **Mobile**: desktop and CLI go first; mobile FFI is untouched.

## 2. Trust Model

- **Trust root = master password + per-device private key**. The local vault unlocks
  with the master password; the sync ciphertext unlocks with the device private key
  (unwraps the group key envelope) → group key → item key. The two are stored
  independently and rotated independently.
- **Server role = pure relay + ciphertext custody**. It stores the oplog, device
  public keys, and envelopes, but holds no key that can decrypt sync data; it does not
  perform merge adjudication (adjudication happens on the client, §7).
- **Server-visible surface** (full list in §9): ciphertext payload, item UUID, kind
  enum, Lamport counter, timestamp, device public key, envelope size. **No plaintext
  names/URLs/usernames whatsoever** — sync entries seal their metadata inside the
  ciphertext region too, so the visible surface is strictly smaller than the local
  SQLite (whose metadata columns are plaintext, as honestly noted in
  STORAGE_AND_SYNC).

## 3. Decision Records

### DR-1 Device key: generated independently, stored in the OS keyring (rejected: derived from the master password)

Each device **generates a one-time X25519 keypair when joining sync**: the private key,
32 random bytes, goes into the OS keyring (service name `persona-device`, alongside
the existing `persona-biometric`/`persona-sync`); the public key goes to the server
with the device registration.

- **Why not derive from the master password**: derivation means changing the master
  password = every device's public key changes = every envelope re-wrapped + every
  device re-registered — upgrading "change password" from a local operation to a
  fleet-wide migration. The device identity key is a long-lived credential and
  should not be coupled to a replaceable authentication passphrase (1Password's
  separation of account password and device Secret Key is the same idea).
- **Fallback when no keyring is available** (headless CLI/container): an explicit
  `--device-key-file` (planned, not implemented; currently only mentioned in
  `core/src/sync/` comments, no CLI flag) writes a 0600 file, and the command
  prints a red warning "this file is equivalent to the device private key; leaking
  it means the device can be impersonated". No keyring and no file parameter =
  sync unavailable (fail-closed; no silently generated ephemeral key).
- **Lost key** = that device identity is void: just re-run the join flow; no other
  device is affected.
- **Algorithms and dependencies**: `x25519-dalek` (the dalek family, extensively
  publicly reviewed) + `hkdf` (RustCrypto, pairs with the existing `sha2`) + the
  existing `aes-gcm`. Envelope format (`persona-dev-env-1`):
  `ephemeral_pub(32) ‖ AES-256-GCM(key = HKDF-SHA256(x25519(eph, device_pub),
info="persona-dev-env-1"), plaintext = group key)`. The composition layer is ~30
  lines of our own code with round-trip + tampering + cross-device failure-path test
  coverage; no heavyweight HPKE dependency is pulled in for this (optional long-term).

### DR-2 Device auth: SRP-6a with the RFC 5054 4096-bit group to start (OPAQUE listed as a long-term upgrade)

Make the `RemoteAuthProvider` in `core/src/auth/remote.rs` real (currently a 129-line
pure mock):

- **Protocol**: SRP-6a with the RFC 5054 4096-bit group (official test vectors exist;
  interoperable across implementations). The math is implemented inline in
  `core/src/auth/srp.rs` (the RustCrypto `srp` 0.6 crate originally considered was
  dropped due to digest-ecosystem drift and is no longer a dependency), handshake
  hash SHA-256; correctness is regression-locked by the official RFC 5054 Appendix B
  vectors (the 1024-bit/SHA-1 interop vectors).
- **Against offline cracking of a leaked verifier**: the client first runs Argon2id
  over "master password ‖ domain-separated salt (`persona-srp-v1` ‖ server salt)"
  (Argon2id v19, m=19 MiB, t=2, p=1 — the argon2 crate defaults, same family as the
  local password-verification hash; local vault unlock is a separate PBKDF2-600k
  path with a different algorithm and parameters, see `KEY_HIERARCHY.md`; lighter
  than the backup-file KDF's 64 MiB/t3 because the login path runs frequently) to
  obtain the SRP private value x — the server stores the SRP verifier, so the cost
  of offline guessing after a leak ≈ the Argon2 cost, on par with local password
  verification.
- **Sessions**: SRP handshake succeeds → both sides derive a session key → the client
  exchanges it for a short-lived access token (minutes-scale TTL); subsequent requests
  use `Authorization: Bearer`. Lockout follows the local 5-attempt semantics.
- **Compatibility hard constraint**: the existing `PERSONA_SERVER_TOKENS` bearer path
  **stays and coexists** — the backup chain (push requires no unlocked master
  password) and event reporting are not disrupted; SRP is the auth method for the
  sync endpoints, not a retrofit across all endpoints.
- **Crate landscape (2026-09 survey, selection rationale)**: RustCrypto `srp` 0.6
  works but is slow to maintain (the PAKEs repo is marked "USE AT YOUR OWN RISK";
  0.7 is stuck at rc and no longer compiles against current dependencies); active
  alternatives include `srp6-rs`. What actually landed: no SRP crate at all — the
  SRP math is inlined into `core/src/auth/srp.rs` following the `srp` 0.6 formulas,
  callers are isolated behind the `RemoteAuthProvider` seam so the implementation
  can be swapped wholesale, and correctness is **regression-locked against the
  official RFC 5054 test vectors**. **OPAQUE (`opaque-ke` 4.x, RFC 9807 finalized,
  prevents server-impersonation attacks and is not offline-crackable from the
  verifier) is listed as a long-term upgrade** — heavy to implement with a deep
  dependency chain; evaluate once the sync path has stabilized; the seam layer
  already reserves room for it.

### DR-3 Envelope direction: group key hierarchy (rejected: per-item per-device recipient list)

- **Sync group key (group key)**: random 256 bits, one per workspace, **never leaves
  a device in plaintext** — on the server it exists only in "device envelope" form
  (one per device, wrapped with that device's X25519 public key, DR-1 format).
- **Sync entry**: `{ciphertext payload (encrypted by item key), item key envelope
  (wrapped by group key)}`. The only difference from a local row is the wrapping
  key: local `wrapped_item_key` is wrapped by the master key (`key_hierarchy.rs`),
  the transport version is wrapped by the group key — **the sync format is therefore
  fully decoupled from the master password** (changing the master password only
  affects local wrapping; the DR-1 derivation approach would have lacked this
  advantage).
- **New device join = O(1) re-wrapping**: any existing device unwraps the group key →
  wraps a new envelope with the new device's public key → uploads. The reason the
  per-item recipient list was rejected (envelope bloat of N devices × all items) is
  right here — 1Password's vault key hierarchy is the same structure.
- **Honest boundary of device removal**: a removed device already knows the group key,
  so **keys to already-synced history cannot be retroactively revoked**. True
  removal = manually triggering "secure rotation" (rotate group key + full re-wrap +
  every device re-pulls), which landed in 2026-09 stage 3d
  (`SyncSession::rotate_group_key`: first take the mutex with a server epoch
  optimistic lock (rotate-begin, 2026-09-24, see §12-2) → drain the old group
  ciphertext's head → re-seal a new envelope for each still-authorized device →
  push-empty full re-wrap; desktop "rotate group key" entry point + honest-boundary
  confirmation copy). Revocation and rotation are separate: phase one only
  "revokes that device's auth and access"; rotation is a manual step afterwards.

### DR-4 Conflict resolution: LWW + client Lamport clocks (rejected: server adjudication / CRDT)

- **Total order**: every item carries `(lamport: u64, device_id: u128)`. Local write
  = local lamport + 1; on pull, local lamport = max(local, received). Comparison:
  higher lamport wins; on ties, lexicographic device_id breaks it — **both ends
  computing independently necessarily reach the same result**.
- **Clock source**: only client Lamport counters are trusted, never any server/wall
  clock; timestamps are display-only.
- **True conflict**: two versions of the same item with equal lamport from different
  devices (the typical offline dual-edit shape) → **keep both versions**: the winner
  takes the primary slot, the loser goes into the same item's conflict area as a
  "conflict copy" (`conflict_of` field), and the user adjudicates merge or choice in
  the UI (adjudication UI is stage 3; stage 2's core layer first guarantees both
  versions survive, with no silent overwrite).
- **Delete = tombstone**: deletions record a tombstone entry (with lamport),
  preventing an offline delete from being resurrected by an older version;
  tombstones are cleaned lazily per retention policy.
- **Server role**: only stores the oplog and forwards by cursor, **making no
  win/lose calls whatsoever** — consistent with "the server is not trusted"; letting
  the server adjudicate means handing merge semantics to a component whose honesty
  we refuse to trust.

## 4. Key Hierarchy (full diagram)

```
主密码 ──Argon2id──> master key ──包──> item key ──加密──> 本地载荷与元数据   （本地存储，现状不变）
                     (验证: Argon2 哈希)    │
                                            └──加密──> 附件文件体            （现状不变）
group key（随机 256b，不落盘不明文上服务器）
  ├──包──> item key（同步传输格式）
  └──被每设备 X25519 公钥包──> device envelope（服务器存这个）
设备私钥（X25519，随机生成，keyring persona-device / 0600 文件 fallback）
主密码 ──Argon2id──> SRP x ──SRP-6a 握手──> 短期 access token              （认证层，DR-2）
```

## 5. Sync Protocol

**oplog entry** (stored one-by-one by the server, independent of change_history —
that is local audit trail containing plaintext metadata, never sent directly over the
sync channel):

```
SyncOp {
  op_id: uuid,          // 幂等去重键
  item_id: uuid,
  kind: enum,           // credential | identity | passkey | …
  op: put | delete,     // delete 时 payload 为空（tombstone）
  lamport: u64,
  device_id: uuid,
  timestamp: rfc3339,   // 仅展示，不参与排序
  payload: Option<{ ciphertext: bytes, wrapped_item_key: bytes }>,  // 全密文
}
```

**Endpoints** (on the existing axum server, `/api/v1/sync/*`, auth = DR-2's SRP
session token):

| Endpoint                   | Method     | Purpose                                            |
| -------------------------- | ---------- | -------------------------------------------------- |
| `/sync/devices`            | POST / GET | Register (public key + device name) / list          |
| `/sync/devices/{id}`       | DELETE     | Revoke that device                                 |
| `/sync/group-keys`         | GET / PUT  | Fetch all device envelopes / upload this device's group key envelope |
| `/sync/oplog`              | POST       | Push new local oplog batches (≤500 entries/batch, following the events convention) |
| `/sync/oplog?since=cursor` | GET        | Pull deltas (cursor pagination)                    |

**Push/pull semantics**: push is idempotent by `op_id`; pull increments from the
since cursor. The server appends in arrival order without sorting or merging (DR-4).
The body limit follows the server's existing 1 MiB/batch; the `/sync/*` subrouter
**has no decompression layer** (ciphertext does not compress; this also avoids a
second decompression-bomb surface), while the 10 MiB decompression defense is only
mounted on the events subrouter (the layered comment in `server/src/lib.rs`;
registered honestly in THREAT_MODEL).

**Capture point**: on the service-layer write path (the same call sites as
change_history), the oplog is generated alongside — plaintext metadata stays only
in the local change_history; the oplog holds only the ciphertext structure of §5.

### Library-level snapshot and instruction compaction (S2 closed out — design finalized 2026-10-07, **full pipeline landed 2026-10-07**)

Motivation: the oplog is an append-only instruction stream, and a new device joining
the group or a long-offline device returning must replay the full instruction set
from its cursor — over the lifetime of a personal credential vault the instruction
count is substantial (rename / rotate password / favorite each produce a new put),
so first-sync duration grows linearly with history. A snapshot = a whole-vault
state package at some seq, letting laggards start "snapshot + post-snapshot
increment".

**Implementation progress** (2026-10-07): ✅ 00010 migration + server PUT/GET
endpoints (transactionally deletes `seq ≤ S`, a30a2ca); ✅ core format layer
`LibrarySnapshotPayload` (seal/open fail-closed + zero-knowledge tests; entries =
the oplog view-sufficient set of original ops, see below); ✅ `SyncRemote` wire
(HttpSyncRemote PUT/GET, 404→None); ✅ engine primitives
`upload_library_snapshot` / `install_library_snapshot` (sentinel cursor
continuation, travel dual gate); ✅ trigger baseline and threshold determination
(migration 018 `sync_state.last_snapshot_seq` MAX semantics +
`UPLOAD_THRESHOLD_OPS` + `engine::library_snapshot_needed`). ✅ service assembly
layer (2026-10-07: `SyncSession::snapshot_payload` / `install_snapshot_ops` +
run_cycle tail threshold trigger and bootstrap install when the cursor is empty;
failures only log, never block); ✅ two-device convergence-equivalence integration
tests (core in-memory remote `snapshot_bootstrap_converges_like_full_replay` +
real TCP `sync_two_device_e2e::snapshot_bootstrap_plus_increment_converges_over_real_tcp`
— A pushes past the threshold triggering the real production upload path, B starts
from the snapshot with pulled==0 and materializes the full set, the watermark sits
at the coverage point, and post-snapshot increments continue to pull as usual,
2026-10-10).

**Snapshot format** (the server sees only a BLOB, zero-knowledge unchanged;
**2026-10-07 implementation revision**: entries changed from the draft's
"credential-table row snapshot" to **the local oplog's view-sufficient set**):

```
LibrarySnapshotPayload {          // bincode 后用 group key AES-256-GCM 整包加密
  created_at: rfc3339,
  ops: Vec<SyncOp>,               // 每条目：主位 op（put 或 tombstone）+ 未裁决冲突副本
}
```

Packing original ops rather than credential-table rows (install = idempotently
insert by op_id into the local oplog + the existing materialization path, reusing
the full pipeline):

- **pending identity not lost**: when a new device lacks the identity row,
  materialization returns `SkippedPendingIdentity` — a credential-table snapshot
  would discard the entry outright while its op has already been compacted (a real
  data hole); an op entering the oplog is held-pending for retry the same way as in
  full replay.
- **conflict copies not lost**: unadjudicated dual versions are part of the "no
  data loss" floor, and conflict ops before the snapshot point would likewise be
  compacted.
- **tombstones present to prevent resurrection** (revision: the draft's
  "tombstones don't enter the snapshot" is void): after `seq ≤ S` is compacted,
  "post-snapshot increments" do not carry pre-snapshot deletions, and a snapshot
  absent of deletions would let a device installing into a non-empty vault
  resurrect already-deleted entries.
- **LWW total order preserved verbatim**: op_id/lamport/device_id are carried
  over intact — "snapshot start + post-snapshot increment == full replay" holds
  per-item under `item_view` (the standard used by the convergence-equivalence
  anchor). GC'd older versions are view-neutral; their absence does not change the
  view.

**LWW convergence semantics (FAQ closed out, 2026-10-07)**: under the instruction
stream (oplog), conflicts are made **explicit** — true conflicts (concurrent dual
writes at the same lamport) keep both versions resident in the oplog, `item_view`
produces primary + conflicts for the adjudication UI to consume; settled cases
(sequential, non-conflicting writes) use **silent LWW** — `compare_ops` total
order, independent of replay order. "Silent LWW as an option" is realized in the
user adjudication UI: the higher version is adopted automatically by default, and
an adjudication that ends in deleting the losing copy = the user explicitly
endorsing the LWW outcome; no separate auto-resolution policy switch exists.

**Coverage semantics (the core answer to races, refined in the implementation to
the watermark standard)**: the client **first drains its local pending-push queue,
then pulls the remote increment** (the cycle order inside `upload_library_snapshot`),
and uses the converged "local synced watermark" (`local_watermark`, the server seq
of the last consumed op) as coverage point S — the snapshot declares coverage of
`seq ≤ S`. The cycle order guarantees every op on the server with seq ≤ S is
already reflected in local state (the draft's "push acked seq" standard would
over-claim the landing interval of concurrent devices; the watermark standard
strictly never over-claims); concurrent pushes by other devices between push/pull
land in the `> S` interval, which pullers fill incrementally from S — no
distributed snapshot-point protocol needed. The threat of a client lying about S
= devices in the group can already push forged entries (§2 trust model, mutual
trust within the group); no new defense is added.

**Endpoints** (two new ones, same auth family as `/sync/*`):

| Endpoint         | Method | Purpose                                                                                                                                       |
| ---------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `/sync/snapshot` | PUT    | Upload the ciphertext package + the client-declared coverage point S; server-side in one transaction: write the snapshot row, delete the superseded old snapshot, delete ops with `seq ≤ S` |
| `/sync/snapshot` | GET    | Return the latest snapshot `{seq, ciphertext}`; 404 if none                                                                                   |

**Merged with the existing oplog retention (2026-10-07 revision, replacing the 410 realignment scheme)**:
the server already has day-based retention (`enforce_oplog_retention`, under the
lenient "a shrunken subset still converges" standard — when post-cursor data is
deleted, the missing part is filled by each end's local source of truth and
idempotent re-push). Snapshot compaction runs in the same direction and is more
precise: the PUT-snapshot transaction deletes ops with `seq ≤ S`, semantically
identical to "retention deleted the old segment" — pull **does not reject, no
410**; a `since` falling before the snapshot point still returns the shrunken
page after the snapshot point. The difference is **empty-vault new devices**:
segments deleted by retention are true data loss for a new device (no local
source of truth to fill from), which the snapshot fills exactly — on bootstrap
the client first GETs the snapshot (on 404 it pulls from empty as before); on a
hit it installs the snapshot and incrementally pulls from the snapshot seq. Old
devices need zero changes. Explicit 410 guidance is left as a follow-up
enhancement (no correctness need under the current lenient standard).

**触发时机**（客户端 engine，第一版保守口径）：① push ack 后
`head_seq − last_snapshot_seq > 1000` → 打包上传（防频繁重打包）；② pull
时落后且本地无对应条目基数大（新设备/空库）→ 先拉快照。判定已落
（2026-10-07）：阈值常量 `sync::snapshot::UPLOAD_THRESHOLD_OPS`（=1000，
CLI/桌面不暴露）+ `engine::library_snapshot_needed(threshold)`（travel 恒
false；基线 = 迁移 018 的 `sync_state.last_snapshot_seq`，上传/装包成功
记账，MAX 语义只进不退）；判定挂进 run_cycle 尾部与 ② 的 bootstrap
调用（游标为空才试）已随装配层批次接线（2026-10-07）。压缩后组版本号
显示不回退：`GET /sync/status` 的 head 按 `max(oplog max seq, 快照 seq)`
（2026-10-10，§5.5「单调版本号」硬要求——oplog 清空不能让设置页的组
最新版本号从 1001 跳回 0）。

**失败面**：快照上传失败不阻断同步周期（尽力而为旁路，与捕获同语义）；
travel 激活期间上传直接报错拒绝、装包整体跳过（与 pull 同闸，退 travel
后下次 bootstrap 照试——游标未动）。快照下载/解封失败 fail-closed 报错
（与单条 `SyncItemSnapshot::open` 同口径——key 不对或被篡改不许静默降级
为全量重放，因为重放区间可能已被压缩删除）；装包回调失败游标不动
（fail-closed 保住全量重放路径，不留半装状态）。服务器存储放大系数 =
1 份快照 ≈ oplog 视图充分集（GC 后 ≈ 当前库密文总量），个人库量级
（几 MB）可接受。

**测试锚点**（实现批次的验收口径）：

- 零知识核查同样适用于快照 BLOB（`capture.rs` 测试口径平移）——✅ 已落
  （`snapshot.rs::library_snapshot_bytes_never_leak_entry_plaintext` 与
  错 key/篡改/截断 fail-closed 回归）。
- 快照起步 + 点后增量 == 全量重放的最终收敛等价性（双真 TCP 设备，一方
  走快照路径）——✅ 已落（2026-10-10，`sync_two_device_e2e` 第 5 例：
  A 推满 1001 ops 越过阈值触发真实上传路径，B 首轮 pulled==0 且物化
  1001 条、水位落在覆盖位点、点后增量照常续拉；core 内存 remote 等价
  性测试互补）。
- 404 → 全量重放回退（初稿「410 重对齐」随 retention 合流修订取消）——
  ✅ 引擎级已落（`install_without_snapshot_keeps_full_replay_path`）。
- 并发 PUT 快照（后到覆盖前者，head 单调）——✅ 已落（2026-10-10：
  `PUT /sync/snapshot` 的 upsert 带 `excluded.seq >= 现存 seq` 条件，
  落后水位 409 拒绝且不附带压缩——否则「快照回退旧 seq + 覆盖区间
  ops 已删」= bootstrap 数据洞；同 seq 重打包幂等放行；两测：
  `snapshot_stale_put_rejected_and_head_monotonic` 与
  `snapshot_concurrent_puts_head_monotonic`）。
- 压缩后老设备增量拉取不受影响——✅ server 端点测试（重传压缩与压缩后
  续拉）+ engine 快照点后续拉增量已落；跨端真 TCP 回归已随收敛等价性
  一并补（2026-10-10，`sync_two_device_e2e` 第 5 例覆盖点后增量）。

## 6. 设备生命周期

- **注册**：生成 X25519 对（DR-1）→ SRP 登录 → `POST /sync/devices`（公钥 +
  设备名）。新设备此时**还读不到 group key**——处于「待授权」。
- **自举**（2026-09 阶段 3c 补）：全新服务器上不存在「既有设备」可代为
  授权——第一台设备 join 时若 `GET /sync/group-keys` 为空，本机生成
  group key 并自封信封上传（`bootstrap_group_if_empty`）。令牌持有者
  本来就能读全部密文，自建组不放大信任面。已知边界：两台设备在彼此
  可见前先后见到空组会各自建组，重复一侧 leave 重走即可。
- **授权**：任一既有设备拆出 group key，为新设备包信封并上传（桌面给设备管理
  页一行确认；CLI 无 sync 子命令（授权经桌面/服务器完成））。未授权设备 pull 不到
  group key，也解不开任何条目——fail-closed。
- **吊销**：设备管理页/CLI 删除该设备：服务器删其公钥与信封，级联删除
  同名 SRP 登记并**即刻吊销**其已签发的短期令牌与未决握手（2026-09 吊销
  闭环——被吊销设备无法用既有凭证继续认证/推送，而非等 TTL 自然过期）。
  前向边界见 DR-3（诚实提示文案照 THREAT_MODEL 风格；历史密文由
  「轮换组密钥」闭环）。
- **恢复**：设备丢失 = 在别处吊销它 + 本机重新走注册授权。主密码不参与设备
  密钥的恢复（无托管原则一致）。

## 7. 冲突解决（操作序）

pull 应用顺序：按 (lamport, device_id) 降序入库；同 item 遇到 lamport 相等但
device 不同的第二条 → 降级为冲突副本（`conflict_of` 指向主位），UI 展示双版本。
合并动作 = 用户在副本上选择字段后「采纳」，产生新 lamport 的 put。**不丢数据、
不静默覆盖**是底线；全自动合并明确不做（§1 非目标）。

## 8. 与既有系统的边界

| 既有资产                                                             | 关系                                                                                                                                                                                                                                                                                       |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 备份链（`/api/v1/backups`、PERSENC1）                                | **不动**。备份是整库快照，同步是凭据级增量；token 共存（DR-2）。恢复整库备份后，本机以 Lamport 重新对齐（备份点之后的远端 oplog 重放）                                                                                                                                                     |
| `change_history`                                                     | 本地审计，含明文元数据，**不上同步通道**；oplog 是独立写入（§5 捕获点）                                                                                                                                                                                                                    |
| 审计事件上报（WireEvent）                                            | 元数据级、本来就不含载荷，与同步无耦合，各走各的                                                                                                                                                                                                                                           |
| **Travel Mode**                                                      | **同步在 travel 激活期间必须整体暂停（push 与 pull 双停）**：enter 事务的批量删除若进 oplog，会把 tombstone 推到其他设备毁库；pull 则可能把被移出身份写回主库，直接违反「主库零痕迹」。exit 恢复后需手动/提示恢复同步。此交互列入 §12 首位开放问题，阶段 2 实现时落地为 push/pull 的前置闸 |
| 桌面 keyring service 集合（`persona-biometric`/`persona-sync` 起步） | 从「双 service」演进为**四 service 并列**：新增 `persona-device`（DR-1）、再增 `persona-biometric-wrap`（2026-09-26 硬件绑定包裹层，`token_store.rs` 常量；见 THREAT_MODEL「Biometric Unlock」）——语义同款：真值在 keyring，库里只留占位                                                   |

## 9. 中转三形态（S3）

同步语义只有一份——§5 的 oplog push/pull + 库级快照压缩，客户端视角
无「哪种服务器」之分；形态只决定**同一协议由谁跑、跑在哪**：

| 形态       | 运行体                                                              | 客户端 base_url               | 定位     |
| ---------- | ------------------------------------------------------------------- | ----------------------------- | -------- |
| 官方托管   | persona 官方部署的 `persona-server`（同一二进制/镜像）              | `https://sync.persona.app` 类 | 默认路径 |
| 自建 relay | 用户自部署 `persona-server`（compose/cargo，`SELF_HOST_SERVER.md`） | 用户自己的 host               | 隐私优先 |
| 局域网直传 | 同一 `persona-server` 绑到现场设备的局域网地址                      | `http://局域网IP:port`        | 零外网   |

三形态共用**同一客户端协议**（core `SyncRemote` 的 wire 语义：
`PUT/GET /sync/snapshot`、`POST /sync/push`、`GET /sync/pull`、
`GET /sync/head`、设备信封分发端点），三形态是**同一 `persona-server`
二进制的三种部署**，不复刻三份实现；LAN 直传只是它绑定在现场设备上。

**验收口径**：三形态一致性测试——同一份 core 集成场景（push/pull/
收敛/快照 bootstrap）对三种 transport 各跑一遍，行为断言完全一致。
差异只允许出现在「传输错误」映射（LAN 断连的错误形状）与配额默认值。

## 10. 服务端可见面与威胁模型登记骨架

`THREAT_MODEL.md`「E2EE 同步中继」章已按本骨架写实（2026-09，阶段 2 批 1–4
落地）。骨架存档：

- **信任根**：主密码 + 设备私钥（§2）。
- **服务端定位与可见面**：纯中继；可见 = 密文、item UUID、kind、lamport、
  时间戳、设备公钥、信封（含尺寸侧信道——诚实登记：条目大小可被服务器观察）。
- **不宣称**：防服务器篡改/回滚/扣留（与备份保管同款）；设备移除的前向安全
  （DR-3）；防恶意服务器无限灌 oplog（配额缓解，不根除）。
- **设备被攻破的爆炸半径**：该设备私钥 → group key → **全部同步数据**（与
  「本机被攻破 = 本库全失」同级，不因同步而放大额外资产——每台设备本来就能
  解全库）。

## 11. 实施阶段映射

| 阶段      | 内容                                                                                                                              | 验收要点                                                                                                       | 威胁模型登记                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --------- | --------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0（本文） | 设计稿                                                                                                                            | 四决策定稿 + 用户确认                                                                                          | 骨架（§9）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 1         | SRP 设备认证：实化 `RemoteAuthProvider`、server 存 verifier（非密码哈希）、SRP 会话换短期 token、与 TOKENS Bearer 共存、锁户 5 次 | RFC 5054 测试向量回归；备份链回归（token 共存不打断）；跨端（CLI↔server）握手集成测试                         | **全流程已落地 2026-09**：服务端 `server/src/api/auth.rs` + 客户端 `core/src/auth/remote_http.rs`（feature `remote-auth`；mock trait 留作 UI seam，真实客户端为独立类型，见 REMOTE_AUTH「Real implementation」）；跨端集成测试 `http_provider_full_round_trip_over_real_tcp`（真 TCP 全流程 + SRP token 过 require_bearer）；THREAT_MODEL「SRP 设备认证端点」章                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 2         | E2EE sync 核心：device envelope（DR-1 格式）、group key 层级、oplog push/pull、LWW+冲突双版本、travel 闸                          | 服务端只见密文的断言测试；断网/重放/乱序容错；换主密码后同步零影响；两端收敛测试（含双端离线编辑冲突保双版本） | **核心已落地 2026-09（批 1–4）**：密码层 `core/src/sync/{keys,envelope}.rs`（group key/设备密钥对/`persona-dev-env-1` 信封）、oplog + LWW/冲突双版本 `core/src/sync/oplog.rs`（DR-4；`conflict_of` 偏差——冲突区由 `item_view` 从 op 集合推导，不落快照列，append-only 免维护）、本地同步存储 `core/src/storage/sync_repository.rs`（014 迁移：oplog/push 队列/游标/时钟）、服务端中继 `server/src/api/sync.rs` + 0004 迁移（设备/信封/oplog 表，`/api/v1/sync/*`）、客户端引擎 `core/src/sync/engine.rs`（push/pull 周期 + Lamport 时钟 + travel 闸）与 `sync/remote.rs`（HTTP wire，cfg `remote-auth`）。验收对应：服务端只见密文（`server_stores_only_ciphertext`）；重放幂等（op_id 双端去重 + INSERT OR IGNORE）；乱序容错（LWW 全序回放顺序无关，`batch_is_order_independent`）；换主密码零影响（引擎全链路无主密码参数，状态全在库，重建实例续用——收敛测试内构造性证明）；两端收敛（`two_devices_converge_over_real_tcp_conflict_keeps_both_versions`：真 TCP，双端同 lamport 离线编辑 → 收敛同一主位 + 双版本密文都在）；travel 闸（`travel_gate_stops_push_and_pull_both`）。THREAT_MODEL「E2EE 同步中继」章 |
| 3         | 端到端接线：desktop 设备管理页 + 冲突裁决 UI + `STORAGE_AND_SYNC.md`「当前没有凭据级实时同步」整节重写                            | 双设备真机同步演示脚本；吊销流程 UI 走查；文档与实现一致                                                       | **已落地 2026-09（3a–3d）**：桌面同步面板与设备管理/授权/吊销（`SettingsModal` 同步节）、冲突裁决弹窗 `SyncConflictsModal`（琥珀横幅+双版本采纳）、`STORAGE_AND_SYNC.md` 重写（双设备演示走查+轮换组密钥+已知边界）、组密钥轮换 `SyncSession::rotate_group_key`（3d，`core/src/sync/runtime.rs`）；复查 §9 清单与实现相符                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| 4         | Connect endpoint：本机 127.0.0.1 HTTP API + scope token（形态 A），默认关闭 fail-closed                                           | 越权/越 scope 拒绝测试；默认关闭断言                                                                           | **已落地 2026-09**：`connect-server/`（axum 内嵌宿主、127.0.0.1 硬绑、Host 白名单防 DNS rebinding→421、scope token 明文只显示一次）+ `persona connect token create/serve`；THREAT_MODEL「Connect 本机自动化端点」章                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

规模预估：10–12 个会话量级，每阶段独立 PR。

## 12. 开放问题

1. **Travel Mode × 同步**（§8）：暂停是够用的答案吗？enter 前是否强制一次
   最终 flush？多设备同时 travel 的语义（两台各自移出不同身份再恢复）？
2. **安全轮换**——**v1 已落地**（2026-09 阶段 3d）：`SyncSession::rotate_group_key`
   （换信封 + 全量重包，§12 语义的字面实现）+ 桌面「轮换组密钥」入口。
   诚实边界已登记于 DR-3 与用户文档：窗口内未推送改动、未裁决冲突副本清出
   视图。**并发轮换已收口**（2026-09-24）：`POST /sync/group-key/rotate-begin`
   以 epoch 乐观锁为「写信封族 + 全量重包」抢占互斥——CAS 命中（epoch ==
   if_epoch）则 epoch +1 并获得写信封窗口，未命中返回 409（客户端映射
   `PersonaError::ConcurrentConflict`，desktop 错误码 `CONCURRENT_CONFLICT`），
   后到者未写信封未重包、干净中止，重读状态后重试即可。epoch 随
   GroupKeysResponse 下发（serde default 0 兼容老服务器——从未轮换语义
   一致，最多多一次误报 409 后重读，方向安全）。**只防诚实客户端的意外
   并发，不防恶意绕过 begin 直接写信封**（写入真实性属开放问题 6 远期
   边界）。**崩溃续跑已钉住**（2026-09-24）：begin 后崩溃留下的信封
   混合态，重试即重跑——残留信封被重试轮新信封 upsert 覆盖（信封行
   不膨胀）、epoch 累计各轮 begin、全组收敛可解（真 TCP 集成测试
   `crashed_mid_rotation_retry_rewrites_envelopes_and_converges` 锁定；
   崩溃轮若已重包一半，重试轮重包以主库为准、LWW 自然成为新主位）。
   **开放问题 2 至此全部收口。**
3. **oplog 增长与墓碑保留策略**——**客户端半边已落地**（2026-09-24）：
   `SyncSession::gc_oplog`（每个同步周期尾部自动运行）按安全谓词清理已消费
   的历史：保护集 = push 未 ack 的 op（推数窗口）、未裁决冲突副本、主位 put；
   可清集 = acked 的旧版本 + ack 且超过 tombstone 保留窗口（默认 30 天，
   `default_tombstone_retention`；timestamp 缺失保守不清）的主位墓碑。裁决
   采纳以更大 lamport 重新入账，败方自动落出副本集、无需 GC 特判；被清 op
   在游标重置重拉时按 op*id 幂等重建，视图不变（谓词矩阵见 runtime 测试）。
   ——**server 半边同日落地**（2026-09-24）：
   `PERSONA_SERVER_OPS_RETENTION_DAYS` / `PERSONA_SERVER_EVENTS_RETENTION_DAYS`
   （0 = 不清理，默认保持纯中继现状；push/ingest 写路径滚动执行，
   `persona*{sync_ops,events}\_pruned_total` 计数）。oplog 窗口语义 =
   放弃向「离线超过窗口」的设备补发历史的责任：游标重置重拉拿到缩水
   子集（LWW 对子集仍收敛），缺失部分靠各端本地事实源 + 重推幂等重建
   （INSERT OR IGNORE 原样回填）补齐——**窗口须 ≥ 最慢设备的离线周期**；
   events 窗口按部署方 SIEM 摘取周期定。**开放问题 3 至此两端收口**，
   剩余为运维参数调优而非机制缺口。
4. **附件同步**：v2 议题——文件体走 oplog（信封化分块）还是保持备份通道，等
   v1 落地后按真实需求定。
5. **OPAQUE 升级路径**（DR-2）：`opaque-ke` 4.x/RFC 9807 成熟度已足够，若同步
   上线后出现 verifier 泄露场景的真实担忧，按 seam 迁移。
6. **设备私钥签名 oplog**（防服务器伪造/回滚历史）：需要 Ed25519 第二密钥，
   远期随「安全轮换」一并评估。
