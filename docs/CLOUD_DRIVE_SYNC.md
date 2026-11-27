# Cloud-Drive Sync Transport (Phase 2)

> Status: **designed and core-implemented** (2026-11-23). This is one of the
> two sync transports designed together with the server transport
> (user directive: "based on something like iCloud, and also via server — design
> both together"). The **server transport is the default**; cloud-drive is the
> transport you pick when you don't want to host or trust a server at all but
> already have a cloud folder (iCloud Drive / Dropbox / Google Drive) on each
> device.

The **protocol is unchanged**: the same command-stream (oplog) engine,
Lamport ordering, LWW conflict resolution, group-key E2EE, and travel gate all
apply. Cloud-drive sync only swaps the **transport** — where the encrypted
command stream and the group-key envelopes live. So this document is about the
transport, not the protocol (see [`E2EE_SYNC_DESIGN.md`](./E2EE_SYNC_DESIGN.md)
and [`sync-group-mode.md`](./sync-group-mode.md) for the protocol).

## 1. Why a cloud folder can be a relay

A cloud-drive folder (iCloud Drive, Dropbox, Google Drive…) is a
**best-effort, eventually-consistent shared filesystem**: every device that
mounts the same folder sees the same files, and the OS cloud agent propagates
changes between devices without any server of our own.

If we write **only ciphertext** into that folder, the cloud provider sees
nothing but opaque bytes — exactly the "zero knowledge" property we get from a
self-hosted relay, but with zero infrastructure to run. The price: the folder
is the trust boundary for **availability** (if you can't access the folder,
you can't sync), and the cloud provider could in principle delete or roll back
files (logged honestly in the threat model — same "don't trust the server"
stance as the cross-device mode).

> ⚠️ **Hard rule** (carried over from `STORAGE_AND_SYNC.md` §"Cloud Drive
> Folders"): **never put a live `identities.db` in a cloud-drive folder.**
> SQLite assumes exclusive write access; a cloud folder's bidirectional sync
> produces conflict copies and real corruption risk. This transport writes only
> per-device op shards, snapshots, and envelopes — all ciphertext, no SQLite.

## 2. Directory layout

```
<cloud_drive_dir>/
├── dev-<device_id>.jsonl           # per-device append-only command shard
├── snapshot-<seq>-<device_id>.bin  # immutable whole-vault snapshot (ciphertext)
├── env-<device_id>.bin             # group-key envelope (X25519-sealed)
├── env-<device_id>.meta.json       # {sealed_by, created_at} for display
├── registry.json                   # device registry {device_id, name, pubkey}
├── watermark-<device_id>.json      # committed per-shard pull positions (GC gate)
└── base-<device_id>.json           # rows physically compacted from a shard (cursor coordinate shift)
```

- **`dev-<device_id>.jsonl`**: one JSON `SyncOp` per line, appended by that
  device only. Append-only; never physically pruned (see §4).
- **`snapshot-<seq>-<device_id>.bin`**: the group-key-encrypted whole-vault
  snapshot (same payload as the server transport's snapshot). Content-addressed
  by `(seq, device_id)`, so concurrent devices never write the same file and no
  CAS/409 gate is needed.
- **`env-<device_id>.bin`**: the group-key envelope for that device, sealed to
  its X25519 public key (same `seal_group_key` as the server transport). The
  group key itself never appears in the folder.
- **`registry.json`**: the device roster (who has joined the group), so a new
  device can discover the group and its members without a server.

All writes are **atomic** (temp file + fsync + rename in the same directory), so
a syncing cloud agent never sees a half-written line or file.

## 3. Command-stream transport (`CloudDriveRemote`)

Implements the same `SyncRemote` trait the server transport implements
(`core/src/sync/engine.rs`), so the engine, oplog, LWW, materializer, snapshot
primitives, and GC are all reused unchanged.

### 3.1 Total order without a server seq

The server assigns a monotonic `seq` (SQLite AUTOINCREMENT). A cloud folder has
no such counter, so the transport **synthesizes** a total order from the data:

- Each op is `(lamport, device_id, op_id)`; op_ids are **globally unique across
  shards** (each op is created by exactly one device and appended to exactly one
  shard).
- The virtual order is the **sort by `(lamport, device_id)`** (op_id breaks the
  rare tie), which is exactly the protocol's LWW order. Any device that reads
  the same shard set computes the same order — deterministic convergence.
- `head_seq` = **sum of all shard line counts** (since op_ids are globally
  unique, this equals the distinct-op count — the same quantity the server's
  `max(oplog.seq, snapshot.seq)` reports).

### 3.2 Resume cursor: per-shard line-count watermark

The server's cursor is `v1:{seq}:{op_id}` (a rank). A rank cursor has a real
hole for a folder: if device B was offline, and B later appends an op with a
**smaller** lamport than ops B already consumed (B wrote lamport 3 after its
shard's later ops), that op sorts **before** B's consumed rank and a rank cursor
would skip it forever.

The cloud transport therefore encodes a **per-shard line-count watermark** into
the cursor, reusing the canonical `v1:` format:

```
cursor = encode_cursor(sum_of_watermarks, "<json map of device -> lines_consumed>")
```

- The `seq` slot holds the sum of per-shard consumed lines (the "high-water
  mark") — so `local_watermark()`, `behind`, and `library_snapshot_needed` all
  keep their meaning **without any change** (they only read the `seq` slot).
- The `op_id` slot holds the JSON map `{"<device_id>": lines}`. The slot is
  opaque to every existing consumer (only non-empty is checked), so reusing it
  is safe.
- `pull_ops` reads **all** un-consumed lines from **each** shard, merges them by
  `(lamport, device_id, op_id)`, and returns them in one page. Because it never
  skips a shard's unconsumed prefix, a late-arriving lower-lamport op is **never
  skipped** — the exact hole a rank cursor has. `limit` is ignored (a local
  folder read; the engine's "stop on empty page" loop still terminates).

The snapshot-resume sentinel the engine writes after installing a snapshot
(`v1:{seq}:0`) decodes to an empty watermark map → full read, which is the safe
direction (re-reads are deduped by op_id; never skips).

### 3.3 `push_ops`

Appends to the device's own shard. Dedup by `op_id` against what's already in
the shard (idempotent — a crash between push and ack is harmless). Writes
atomically.

## 4. Library snapshots: immutable, safe shard-rewrite compaction

The server prunes ops covered by a snapshot (`seq ≤ S`) in the same transaction
— real compaction. A cloud folder has **no cross-device transaction**, so the
cloud transport rewrites each shard **locally** (temp + fsync + rename) during
a *new* snapshot upload, dropping only rows every registered device has
durably consumed.

So the cloud transport:

- writes snapshots as **immutable** files `snapshot-<seq>-<device_id>.bin`
  (never overwritten; content-addressed by `(seq, device_id)`);
- `get_library_snapshot` returns the **max-seq** file (deterministic convergence
  point when several devices upload);
- on a new snapshot, runs **shard-rewrite GC**: returns the number of rows
  dropped (0 when nothing is safe to drop), and only the covered prefix is
  removed — no cross-device delete.

### Safe watermark (fail-closed)

Each device publishes a `watermark-<device_id>.json` file containing its
**committed** per-shard row counts — the positions decoded from the pull cursor
the engine has already persisted (landed ops + cursor write). Publishing lags
one pull cycle behind, so a crash between pull and cursor commit can never
advertise rows as consumed that were never stored locally.

For a given shard, the compaction boundary is the **minimum consumed count
across every device in `registry.json`**:

- a device with **no watermark file** (never pulled / offline before its first
  cycle) → **no compaction at all** for that shard;
- a device whose count lags → the boundary stops at its position, so its
  unconsumed rows survive;
- a removed device no longer gates compaction (its watermark file is deleted
  on removal).

Because all devices must agree on the boundary, a single offline device holds
the line — the conservative direction. Once it comes back and completes a pull
cycle, the next snapshot upload reclaims the common prefix. The rewritten lines
are reserialized from parsed `SyncOp`s (malformed lines are skipped at read time
and not reintroduced) and the rewrite is atomic, so the cloud agent never sees
a half-shard.

**Cursor coordinates**: cursor watermarks are **logical** row numbers that never
decrease. Each shard has a `base-<device_id>.json` recording how many leading
rows were physically dropped. `pull_ops` subtracts the base when indexing the
physical file, so compaction never invalidates a device's cursor — a lagging
device resumes from its logical position and reads exactly the rows still
present. `head_seq` adds back the base, keeping the group version number (and
`local_watermark`/`behind`) monotonic across compactions.

**Honest trade-off**: compaction requires every registered device to be caught
up; an offline device blocks reclamation of the shared prefix indefinitely.
The snapshot is still a logical checkpoint for new devices (install it, then
pull only the delta), and the shards are the safety net until the boundary is
safe.

## 5. Group-key envelopes (`CloudGroupKeyStore`)

The server stores envelopes in a table; the cloud stores them as files:

- `register_device(identity)` appends to `registry.json` (idempotent per
  device; same-name duplicate rejected, mirroring the server's 409).
- `put_group_key(device_id, envelope)` writes `env-<device_id>.bin` +
  `env-<device_id>.meta.json`; **fails if the device isn't registered**
  (fail-closed, same as the server's "ghost device" rejection).
- `group_keys()` reads the registry and each `env-<device_id>.bin` (skipping
  registered-but-not-yet-authorized devices, i.e. those with no envelope —
  the "pending authorization" state).
- `bootstrap_group_if_empty` generates a fresh group key, seals it to the
  caller's public key, and writes its own envelope — same semantics as the
  server.

The envelope exchange is a separate trait (`GroupKeyStore`) from the command
stream (`SyncRemote`), so `SyncSession::open_with` can assemble **either**
transport uniformly. `HttpGroupKeyStore` wraps `SyncAdminApi` with zero behavior
change; `CloudGroupKeyStore` is the file version.

## 6. Session assembly

`SyncSession::open_with(db, identity, remote, key_store, travel)` is the
transport-agnostic body (fetch envelopes → open own envelope → build engine).
Both transports delegate to it:

- `SyncSession::open` (server) = `open_with(HttpSyncRemote, HttpGroupKeyStore)`
- `SyncSession::open_cloud(db, identity, cloud_dir, travel)` =
  `open_with(CloudDriveRemote, CloudGroupKeyStore)`

`cloud_dir` is the **local path** to the cloud-drive folder on this device (the
OS cloud agent does the cross-device propagation). `open_cloud` does not need a
server URL or token at all.

## 7. Configuration surface

`SyncConfig` (the vault settings JSON) gains two fields, both serde-defaulted
so old JSON keeps working:

```rust
pub cloud_drive_dir: Option<String>,   // local path to the cloud-drive folder
pub sync_transport: SyncTransport,     // Server (default) | Cloud
```

- `sync_transport` chooses which transport `sync_now` uses; `Server` is the
  default (existing behavior unchanged).
- `cloud_drive_dir` is the folder path (not secret — it lives in the JSON, not
  the keyring).
- `set_sync_config` (the Tauri command that writes server config) **preserves**
  these two fields — editing server settings must not silently reset the
  transport choice.

The desktop host wires the transport selection through a Tauri command
`set_sync_transport` (narrow write: transport + optional folder; a blank folder
preserves the old one, and cloud requires a non-empty one). `open_sync_session`
routes to the server or cloud session, and the cloud device lifecycle
(`sync_join` / `sync_leave` / `sync_list_devices` / `sync_authorize` /
`sync_revoke` / `sync_set_device_remark`) is exposed to the UI. The settings UI
renders both: a transport selector (server / cloud folder) with the cloud
folder picker (`@tauri-apps/plugin-dialog`), backed by these fields.

## 8. Transport comparison

|                     | Server (persona-server)     | Cloud drive                          |
| ------------------- | --------------------------- | ------------------------------------ |
| Infra               | must host / trust a server  | none — an OS cloud folder            |
| seq                 | server AUTOINCREMENT        | synthesized `(lamport, device_id)`   |
| cursor              | rank `(seq, op_id)`         | per-shard line-count watermark       |
| late low-lamport op | never (server order)        | never skipped (watermark)            |
| compaction          | snapshot prunes covered ops | none (immutable, shards append-only) |
| snapshot CAS        | 409 gate                    | content-addressed filename           |
| device roster       | server table                | `registry.json` + `env-*.bin`        |
| trust               | relay zero-knowledge        | provider sees ciphertext only        |

## 9. Open questions / follow-ups

1. **Desktop settings UI** (landed): the settings page renders a transport
   selector (server / cloud drive folder) in `SyncTransportSection` — switching
   to cloud without a folder opens the OS folder picker first and saves the
   pair atomically; switching back to server preserves the configured folder.
   No optimistic flips: writes are backfilled from the returned server truth.
2. **Change watcher** (landed): the desktop host runs a supervisor task
   (`src-tauri/src/sync_watcher.rs`) that re-evaluates the sync config every
   ~5s and, when the transport is `cloud` with a configured folder, watches the
   protocol files (`dev-*.jsonl` / `snapshot-*.bin` / `env-*` /
   `registry.json`). Primary source is `notify` (best-effort — falls back
   silently on network filesystems or watch-start failure); the polling fallback
   is a 30s mtime+size fingerprint of the protocol files that fires only on
   change. On a change it runs a full `sync_cycle_once` (the same orchestration
   as `sync_now`), debounced by the 5s supervisor tick, and suppresses the
   feedback loop (its own push writes the shards, which would re-trigger) by
   refreshing the baseline fingerprint to the post-cycle state. Core stays
   dependency-free (`notify` is a desktop-only dependency).
3. **Shard growth** (landed): shard-rewrite GC (§4) compacts the common consumed
   prefix on each new snapshot upload. An offline device blocks compaction
   (fail-closed); once it catches up the next snapshot reclaims the prefix.
4. **Cloud folder availability** (landed): sync only works when the folder is
   reachable and the OS agent has propagated changes. The host classifies the
   cycle failure structurally — a transport-layer I/O failure under the cloud
   transport carries `SYNC_CLOUD_FOLDER_UNAVAILABLE`, under the server
   transport `SYNC_SERVER_UNREACHABLE` (written into
   `ApiResponse.error_code`, the channel the sync UI already uses for
   `CONCURRENT_CONFLICT`) — so the settings screen points the user at the
   folder / cloud agent versus the server URL and token. Gate failures (locked,
   not joined, folder not configured) carry no code and keep the generic
   message.
