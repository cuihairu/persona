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
master password ──Argon2id──> master key ──wrap──> item key ──encrypt──> local payload & metadata   (local storage, unchanged)
                     (verify: Argon2 hash)    │
                                            └──encrypt──> attachment file body            (unchanged)
group key (random 256b, never written to disk, never sent to the server in plaintext)
  ├──wrap──> item key (sync transport format)
  └──wrapped by each device's X25519 public key──> device envelope (this is what the server stores)
device private key (X25519, randomly generated, keyring persona-device / 0600 file fallback)
master password ──Argon2id──> SRP x ──SRP-6a handshake──> short-lived access token              (auth layer, DR-2)
```

## 5. Sync Protocol

**oplog entry** (stored one-by-one by the server, independent of change_history —
that is local audit trail containing plaintext metadata, never sent directly over the
sync channel):

```
SyncOp {
  op_id: uuid,          // idempotency / dedup key
  item_id: uuid,
  kind: enum,           // credential | identity | passkey | …
  op: put | delete,     // payload empty on delete (tombstone)
  lamport: u64,
  device_id: uuid,
  timestamp: rfc3339,   // display only, not used for ordering
  payload: Option<{ ciphertext: bytes, wrapped_item_key: bytes }>,  // fully encrypted
}
```

**Endpoints** (on the existing axum server, `/api/v1/sync/*`, auth = DR-2's SRP
session token):

| Endpoint                   | Method     | Purpose                                                                            |
| -------------------------- | ---------- | ---------------------------------------------------------------------------------- |
| `/sync/devices`            | POST / GET | Register (public key + device name) / list                                         |
| `/sync/devices/{id}`       | DELETE     | Revoke that device                                                                 |
| `/sync/group-keys`         | GET / PUT  | Fetch all device envelopes / upload this device's group key envelope               |
| `/sync/oplog`              | POST       | Push new local oplog batches (≤500 entries/batch, following the events convention) |
| `/sync/oplog?since=cursor` | GET        | Pull deltas (cursor pagination)                                                    |

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
LibrarySnapshotPayload {          // bincode then encrypted whole with group key AES-256-GCM
  created_at: rfc3339,
  ops: Vec<SyncOp>,               // per entry: primary op (put or tombstone) + unadjudicated conflict copies
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

| Endpoint         | Method | Purpose                                                                                                                                                                                     |
| ---------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/sync/snapshot` | PUT    | Upload the ciphertext package + the client-declared coverage point S; server-side in one transaction: write the snapshot row, delete the superseded old snapshot, delete ops with `seq ≤ S` |
| `/sync/snapshot` | GET    | Return the latest snapshot `{seq, ciphertext}`; 404 if none                                                                                                                                 |

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

**Trigger timing** (client engine, conservative first-cut standard): ① after push
ack, `head_seq − last_snapshot_seq > 1000` → pack and upload (prevents frequent
re-packing); ② when lagging on pull and the local entry cardinality is small
relative to the gap (new device / empty vault) → pull the snapshot first. The
determination landed (2026-10-07): threshold constant
`sync::snapshot::UPLOAD_THRESHOLD_OPS` (=1000, not exposed to CLI/desktop) +
`engine::library_snapshot_needed(threshold)` (always false under travel; baseline
= migration 018's `sync_state.last_snapshot_seq`, recorded on successful upload /
install, MAX semantics — only ever moves forward); the determination is wired into
the run_cycle tail and the ② bootstrap call (only attempted when the cursor is
empty) along with the assembly-layer batch (2026-10-07). The group version number
display does not regress after compaction: the head in `GET /sync/status` is
`max(oplog max seq, snapshot seq)` (2026-10-10, the §5.5 "monotonic version
number" hard requirement — clearing the oplog must not make the group's latest
version on the settings page jump back from 1001 to 0).

**Failure surface**: a snapshot upload failure does not block the sync cycle
(best-effort side path, same semantics as capture); while travel is active,
uploads are refused outright with an error and installs are skipped wholesale
(same gate as pull; after leaving travel the next bootstrap tries as before —
the cursor never moved). Snapshot download/unseal failure is a fail-closed error
(same standard as a single `SyncItemSnapshot::open` — a wrong key or tampering
must not silently degrade to full replay, because the replay range may already
have been compacted away); an install callback failure leaves the cursor
untouched (fail-closed, preserving the full-replay path, leaving no half-installed
state). Server storage amplification factor = 1 snapshot ≈ the oplog's
view-sufficient set (after GC ≈ total ciphertext of the current vault),
acceptable at personal-vault scale (a few MB).

**Test anchors** (acceptance criteria for the implementation batches):

- Zero-knowledge checks apply equally to the snapshot BLOB (the `capture.rs`
  test standard carried over) — ✅ landed
  (`snapshot.rs::library_snapshot_bytes_never_leak_entry_plaintext` plus
  wrong-key/tampered/truncated fail-closed regressions).
- Snapshot bootstrap + post-point increments == final-convergence equivalence
  with full replay (two real-TCP devices, one taking the snapshot path) —
  ✅ landed (2026-10-10, `sync_two_device_e2e` case 5: A pushes past 1001
  ops crossing the threshold triggering the real upload path, B's first round
  pulled==0 and materializes 1001 entries, the watermark lands at the
  coverage point, post-point increments continue to pull as usual;
  complemented by the core in-memory remote equivalence test).
- 404 → full-replay fallback (the draft's "410 realignment" was dropped with
  the retention-confluence revision) — ✅ landed at engine level
  (`install_without_snapshot_keeps_full_replay_path`).
- Concurrent PUT snapshots (later one supersedes earlier, head monotone) —
  ✅ landed (2026-10-10: `PUT /sync/snapshot` upsert carries an
  `excluded.seq >= existing seq` condition, stale watermarks rejected with
  409 and no compaction attached — otherwise "snapshot regressing to an old
  seq + covered-range ops already deleted" = a bootstrap data hole; same-seq
  repacking allowed idempotently; two tests:
  `snapshot_stale_put_rejected_and_head_monotonic` and
  `snapshot_concurrent_puts_head_monotonic`).
- Post-compaction incremental pulls by old devices unaffected — ✅ server
  endpoint tests (re-push compaction and post-compaction continued pulls) +
  engine post-snapshot-point incremental pulls landed; cross-end real-TCP
  regression added along with the convergence equivalence (2026-10-10,
  `sync_two_device_e2e` case 5 covers post-point increments).

## 6. Device Lifecycle

- **Registration**: generate an X25519 pair (DR-1) → SRP login →
  `POST /sync/devices` (public key + device name). At this point the new
  device **still cannot read the group key** — it sits in "pending
  authorization".
- **Bootstrap** (added 2026-09, stage 3c): on a brand-new server no "existing
  device" exists to authorize on its behalf — when the first device joins and
  `GET /sync/group-keys` is empty, that device generates the group key and
  uploads a self-addressed envelope (`bootstrap_group_if_empty`). A token
  holder can already read all ciphertext, so self-created groups enlarge no
  trust surface. Known edge: two devices seeing the empty group in sequence
  before becoming visible to each other will each create a group; leave on
  the duplicate side and redo the flow.
- **Authorization**: any existing device unwraps the group key, wraps an
  envelope for the new device, and uploads it (desktop adds a one-line
  confirmation on the device management page; the CLI has no sync subcommand
  (authorization goes through desktop/server)). An unauthorized device cannot
  pull the group key or decrypt any entry — fail-closed.
- **Revocation**: the device management page / CLI deletes the device: the
  server deletes its public key and envelope, cascades deletion of the SRP
  registration under the same name, and **immediately revokes** its issued
  short-lived tokens and pending handshakes (2026-09 revocation loop — a
  revoked device cannot keep authenticating/pushing with existing
  credentials, rather than waiting out the TTL). Forward-secrecy boundary:
  see DR-3 (honest prompt copy follows THREAT_MODEL style; historical
  ciphertext is closed out by "rotate group key").
- **Recovery**: a lost device = revoke it elsewhere + redo registration and
  authorization on the new machine. The master password plays no part in
  recovering device keys (consistent with the no-escrow principle).

## 7. Conflict Resolution (operation order)

Pull application order: insert in descending (lamport, device_id) order; a second
op on the same item with equal lamport but a different device → demoted to a
conflict copy (`conflict_of` pointing at the primary), the UI shows both versions.
Merging = the user selecting fields on the copy and "adopting", producing a
new-lamport put. **No data loss, no silent overwrite** is the floor; fully
automatic merging is explicitly not done (§1 non-goal).

## 8. Boundaries with Existing Systems

| Existing asset                                                                 | Relationship                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Backup chain (`/api/v1/backups`, PERSENC1)                                     | **Untouched**. A backup is a whole-vault snapshot; sync is credential-level deltas; tokens coexist (DR-2). After restoring a whole-vault backup, this machine re-aligns by Lamport (replaying the remote oplog past the backup point)                                                                                                                                                                                                                                                                                    |
| `change_history`                                                               | Local audit trail containing plaintext metadata, **never sent over the sync channel**; the oplog is written independently (§5 capture point)                                                                                                                                                                                                                                                                                                                                                                             |
| Audit event reporting (WireEvent)                                              | Metadata-level and carries no payloads to begin with; no coupling with sync, each travels its own lane                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **Travel Mode**                                                                | **Sync must be suspended wholesale while travel is active (both push and pull stopped)**: the enter transaction's batch deletes, if they entered the oplog, would push tombstones to other devices and corrupt those vaults; a pull could write a de-homed identity back into the primary vault, directly violating "zero trace in the primary vault". After exit, sync must be resumed manually or by prompt. This interaction is listed as the first open question in §12 and lands in stage 2 as a push/pull pre-gate |
| Desktop keyring service set (starting from `persona-biometric`/`persona-sync`) | Evolves from "two services" to **four parallel services**: adds `persona-device` (DR-1), then `persona-biometric-wrap` (2026-09-26 hardware-bound wrapping layer, `token_store.rs` constant; see THREAT_MODEL "Biometric Unlock") — same semantics: the real value lives in the keyring, the database keeps only a placeholder                                                                                                                                                                                           |

## 9. Three Relay Forms (S3)

There is one and only one sync semantic — §5's oplog push/pull + vault-level
snapshot compaction; from the client's perspective there is no distinction of
"which server"; the form only decides **who runs the same protocol and where**:

| Form              | Runner                                                                     | Client base_url                           | Positioning           |
| ----------------- | -------------------------------------------------------------------------- | ----------------------------------------- | --------------------- |
| Officially hosted | persona's officially deployed `persona-server` (same binary/image)         | something like `https://sync.persona.app` | Default path          |
| Self-hosted relay | user-self-deployed `persona-server` (compose/cargo, `SELF_HOST_SERVER.md`) | user's own host                           | Privacy first         |
| LAN direct        | the same `persona-server` bound to the on-site device's LAN address        | `http://<LAN IP>:port`                    | Zero external network |

All three forms share **the same client protocol** (the wire semantics of core
`SyncRemote`: `PUT/GET /sync/snapshot`, `POST /sync/push`, `GET /sync/pull`,
`GET /sync/head`, device-envelope distribution endpoints); the three forms are
**three deployments of the same `persona-server` binary** — no three separate
implementations; LAN direct is just it bound to the on-site device.

**Acceptance criteria**: three-form consistency tests — the same core
integration scenarios (push/pull/convergence/snapshot bootstrap) run once per
transport, with behavior assertions identical across all three. Differences are
allowed only in "transport error" mapping (the error shape of a LAN disconnect)
and quota defaults.

## 10. Server-Visible Surface and Threat Model Registration Skeleton

The "E2EE Sync Relay" chapter of `THREAT_MODEL.md` is written out per this
skeleton (2026-09, stage 2 batches 1–4 landed). Archived skeleton:

- **Trust root**: master password + device private key (§2).
- **Server role and visible surface**: pure relay; visible = ciphertext,
  item UUID, kind, lamport, timestamp, device public key, envelope (including
  a size side channel — honestly registered: entry size is observable by the
  server).
- **Not claimed**: protection against server tampering / rollback / withholding
  (same as backup custody); forward secrecy of device removal (DR-3);
  protection against a malicious server flooding the oplog (quota mitigation,
  not root-caused).
- **Blast radius of a compromised device**: that device's private key → group
  key → **all synced data** (on par with "this machine compromised = this
  vault fully lost"; sync amplifies no extra assets — every device can
  already decrypt the whole vault).

## 11. Implementation Stage Mapping

| Stage             | Content                                                                                                                                                                                                  | Acceptance focus                                                                                                                                                                                                                                      | Threat model registration                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (this document) | Design draft                                                                                                                                                                                             | Four decisions finalized + user sign-off                                                                                                                                                                                                              | Skeleton (§9)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| 1                 | SRP device authentication: implement `RemoteAuthProvider`, server stores verifier (not password hash), SRP session exchanges for short-lived token, coexist with TOKENS Bearer, lockout after 5 failures | RFC 5054 test vector regression; backup chain regression (token coexistence doesn't break it); cross-end (CLI↔server) handshake integration tests                                                                                                    | **Full flow landed 2026-09**: server `server/src/api/auth.rs` + client `core/src/auth/remote_http.rs` (feature `remote-auth`; mock trait kept as UI seam, the real client is a separate type, see REMOTE_AUTH "Real implementation"); cross-end integration test `http_provider_full_round_trip_over_real_tcp` (real TCP full flow + SRP token through require_bearer); THREAT_MODEL "SRP Device Authentication Endpoints" chapter                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 2                 | E2EE sync core: device envelope (DR-1 format), group key hierarchy, oplog push/pull, LWW + conflict dual-version, travel gate                                                                            | assertion tests that the server sees only ciphertext; network-loss / replay / out-of-order tolerance; zero sync impact after master password change; two-end convergence tests (including dual-end offline edits with conflict keeping both versions) | **Core landed 2026-09 (batches 1–4)**: crypto layer `core/src/sync/{keys,envelope}.rs` (group key / device key pair / `persona-dev-env-1` envelope), oplog + LWW/conflict dual-version `core/src/sync/oplog.rs` (DR-4; `conflict_of` deviation — the conflict set is derived by `item_view` from the op set, not a snapshot column, append-only maintenance-free), local sync storage `core/src/storage/sync_repository.rs` (014 migration: oplog / push queue / cursor / clock), server relay `server/src/api/sync.rs` + 0004 migration (devices / envelopes / oplog tables, `/api/v1/sync/*`), client engine `core/src/sync/engine.rs` (push/pull cycle + Lamport clock + travel gate) and `sync/remote.rs` (HTTP wire, cfg `remote-auth`). Acceptance mapping: server sees only ciphertext (`server_stores_only_ciphertext`); replay idempotent (op_id dedup on both ends + INSERT OR IGNORE); out-of-order tolerant (LWW total order makes replay order irrelevant, `batch_is_order_independent`); zero master-password impact (the engine takes no master password parameter end to end, all state lives in the vault, rebuilt instances continue — constructively proven within the convergence test); two-end convergence (`two_devices_converge_over_real_tcp_conflict_keeps_both_versions`: real TCP, both ends edit offline at the same lamport → converge on the same primary + both versions' ciphertext present); travel gate (`travel_gate_stops_push_and_pull_both`). THREAT_MODEL "E2EE Sync Relay" chapter |
| 3                 | End-to-end wiring: desktop device management page + conflict adjudication UI + `STORAGE_AND_SYNC.md` "currently there is no credential-level real-time sync" section rewritten in full                   | two-device real-machine sync demo script; revocation flow UI walkthrough; docs consistent with implementation                                                                                                                                         | **Landed 2026-09 (3a–3d)**: desktop sync panel with device management / authorization / revocation (sync section of `SettingsModal`), conflict adjudication dialog `SyncConflictsModal` (amber banner + dual-version adoption), `STORAGE_AND_SYNC.md` rewrite (two-device demo walkthrough + group key rotation + known edges), group key rotation `SyncSession::rotate_group_key` (3d, `core/src/sync/runtime.rs`); re-checked the §9 checklist against the implementation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| 4                 | Connect endpoint: local 127.0.0.1 HTTP API + scope token (form A), disabled by default fail-closed                                                                                                       | out-of-authorization / out-of-scope rejection tests; disabled-by-default assertion                                                                                                                                                                    | **Landed 2026-09**: `connect-server/` (axum embedded host, hard-bound to 127.0.0.1, Host allowlist preventing DNS rebinding→421, scope token plaintext shown only once) + `persona connect token create/serve`; THREAT_MODEL "Connect Local Automation Endpoint" chapter                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

Scale estimate: on the order of 10–12 sessions, one independent PR per stage.

## 12. Open Questions

1. **Travel Mode × sync** (§8): is suspending a sufficient answer? Should there
   be a mandatory final flush before enter? Semantics of multiple devices
   traveling at once (two devices each de-homing a different identity and then
   restoring)?
2. **Security rotation** — **v1 landed** (2026-09, stage 3d):
   `SyncSession::rotate_group_key` (re-wrap envelopes + full re-pack, the
   literal implementation of the §12 semantics) + a desktop "rotate group key"
   entry point. The honest boundaries are registered in DR-3 and the user
   docs: changes not pushed within the window, and unadjudicated conflict
   copies dropping out of the view. **Concurrent rotation is closed out**
   (2026-09-24): `POST /sync/group-key/rotate-begin` uses an epoch optimistic
   lock to preempt "write envelope family + full re-pack" mutually exclusively
   — a CAS hit (epoch == if_epoch) increments epoch by 1 and grants the
   envelope-writing window; a miss returns 409 (mapped on the client to
   `PersonaError::ConcurrentConflict`, desktop error code
   `CONCURRENT_CONFLICT`), and the later arriver writes no envelopes and
   re-packs nothing, aborting cleanly — just re-read state and retry. The epoch
   is delivered with GroupKeysResponse (serde default 0 for old-server
   compatibility — the never-rotated semantics line up, at worst one spurious
   409 before a re-read, directionally safe). **This only prevents accidental
   concurrency from honest clients, not malicious bypass of begin to write
   envelopes directly** (write authenticity is a long-term boundary under open
   question 6). **Crash continuation is pinned down** (2026-09-24): the mixed
   envelope state left by a crash after begin is recovered by a retry that
   simply reruns — leftover envelopes are upserted over by the retry round's
   new envelopes (the envelope rows don't bloat), the epoch accumulates across
   begin rounds, and the whole group converges to a decodable state (locked by
   the real-TCP integration test
   `crashed_mid_rotation_retry_rewrites_envelopes_and_converges`; if the
   crashed round had already re-packed halfway, the retry round's re-pack
   defers to the primary vault and LWW naturally makes it the new primary).
   **Open question 2 is now fully closed.**
3. **oplog growth and tombstone retention policy** — **client half landed**
   (2026-09-24): `SyncSession::gc_oplog` (runs automatically at the tail of
   every sync cycle) prunes consumed history by safety predicate: the protected
   set = ops not yet acked by push (the push window), unadjudicated conflict
   copies, primary puts; the clearable set = acked older versions + primary
   tombstones that are acked and past the tombstone retention window (default
   30 days, `default_tombstone_retention`; conservatively not cleared when
   timestamp is missing). Adjudication adoption re-books at a higher lamport,
   so the loser drops out of the copy set automatically — no GC special case
   needed; cleared ops are rebuilt idempotently by `op_id` on cursor-reset
   re-pulls, view unchanged (predicate matrix in the runtime tests).
   — **server half landed the same day** (2026-09-24):
   `PERSONA_SERVER_OPS_RETENTION_DAYS` / `PERSONA_SERVER_EVENTS_RETENTION_DAYS`
   (0 = no pruning, the default keeps the pure-relay status quo; the
   push/ingest write path enforces it on a rolling basis, counted by
   `persona*{sync_ops,events}\_pruned_total`). oplog window semantics =
   giving up the responsibility of backfilling history to "devices offline
   beyond the window": a cursor-reset re-pull gets a shrunken subset (LWW
   still converges on a subset), and the missing part is completed by each
   end's local source of truth + idempotent re-push (INSERT OR IGNORE
   backfills verbatim) — **the window must be ≥ the slowest device's offline
   period**; the events window is set to the deployer's SIEM extraction cycle.
   **Open question 3 is now closed out on both ends**, with only ops parameter
   tuning left rather than a mechanism gap.
4. **Attachment sync**: a v2 topic — whether file bodies go through the oplog
   (enveloped chunking) or stay on the backup channel, to be decided by real
   demand once v1 lands.
5. **OPAQUE upgrade path** (DR-2): `opaque-ke` 4.x/RFC 9807 maturity is
   sufficient; if sync goes live and genuine concerns about verifier leakage
   scenarios emerge, migrate via the seam.
6. **Device private key signing the oplog** (to prevent server-forged /
   rolled-back history): needs a second Ed25519 key, to be evaluated
   long-term together with "security rotation".
