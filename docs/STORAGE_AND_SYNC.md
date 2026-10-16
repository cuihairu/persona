# Storage and Sync Modes (User Guide)

> [English](STORAGE_AND_SYNC.md) | [中文](STORAGE_AND_SYNC.zh.md)

Persona is **local-first**: your vault is always a single encrypted SQLite file on
one device, and every network capability is an **optional add-on**. This guide
explains where your data actually lives, what sync/backup options exist, and
how to configure each one together with its security boundaries.

> For the engineering-oriented architecture design, see
> [`CLIENT_COMMUNICATION_ARCHITECTURE.md`](./CLIENT_COMMUNICATION_ARCHITECTURE.md)
> (vision design draft) and [`THREAT_MODEL.md`](./THREAT_MODEL.md) (threats and
> non-claims).

## Overview: Storage and Sync Modes

| Mode                                      | Status           | What you get                                                         | What you need                       |
| ----------------------------------------- | ---------------- | -------------------------------------------------------------------- | ----------------------------------- |
| **Pure local** (default)                  | Fully usable     | Zero network, full feature set                                       | Nothing to configure                |
| **Self-hosted Persona Server**            | Implemented      | Off-site copy of audit events + encrypted whole-vault backup custody | One server you control              |
| **E2EE credential sync** (desktop)        | Implemented      | Credential consistency across devices (server sees only ciphertext)  | Mode-2 server + ≥2 devices          |
| **Cloud drive folder (iCloud/Dropbox/…)** | Cold backup only | Put encrypted backup files in your cloud drive                       | Manual copy (see the warning below) |

**Credential-level sync is implemented** (2026-09, desktop): two or more devices
relay ciphertext oplogs through a self-hosted server so that credential
additions, edits, and deletions converge across devices; concurrent offline
edits to the same credential keep both versions, with you adjudicating in the
UI. The server only ever sees ciphertext. For details and boundaries, see the
"[End-to-End Encrypted Credential Sync](#end-to-end-encrypted-credential-sync-multi-device)" section
below.

## Where Your Data Lives

The initialized workspace directory (default `~/.persona`, overridable via
`--path` or `PERSONA_WORKSPACE_PATH`):

| Path                                     | Contents                                                                     | Encrypted?                                                                                                        |
| ---------------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `identities.db`                          | Main database: all tables for identities, credentials, audit, settings, etc. | Credential payloads encrypted per-item key; **metadata columns (name, URL, username, etc.) are plaintext SQLite** |
| `attachments/`                           | Attachment file bodies                                                       | Ciphertext (reuses the owning credential's item key)                                                              |
| `backups/`, `exports/`, `temp/`, `logs/` | Working directories (export file path chosen via `--out`)                    | Mixed (export is optionally encrypted)                                                                            |
| `config.toml`                            | CLI configuration                                                            | **Plaintext, contains no keys**                                                                                   |

Key hierarchy: each credential has one random item key (AES-256-GCM encrypts the
payload), and the item key is wrapped by the master key derived from your
master password — see [`KEY_HIERARCHY.md`](./KEY_HIERARCHY.md). The master
password is stored in no file (verification uses an Argon2 hash); once
fingerprint unlock is enabled the master password is held in the OS keychain
(service name `persona-biometric`; see the THREAT_MODEL "Biometric Unlock"
section for the inherent-exposure discussion).

> **Note**: the main database's metadata columns are plaintext. For scenarios
> where even the metadata must stay confidential (shared machines, seized
> devices), consider Travel Mode (see below) or full-disk encryption.

## Mode One: Pure Local (Default)

With no server configured Persona makes **zero external calls** — no telemetry,
no update checks, no network traffic of any kind.

Cold backup recommendations, in order of preference:

1. **Encrypted export**: `persona export --encrypt --out vault-backup.persenc`
   (Argon2id + AES-256-GCM, with an independent passphrase set at export time).
   The file can be copied freely to a USB stick or cloud drive.
2. **Whole-database encrypted backup**: requires the Mode Two server
   (`persona backup push` has no "back up to a local file" path; offline
   recovery can use `persona backup restore --file` to consume any `.persenc`
   ciphertext).
3. OS-level snapshots: before copying `identities.db` directly, lock or quit
   Persona first (hot-copying a live SQLite database risks corruption).

## Mode Two: Self-Hosted Persona Server

### What You Get

1. **Off-site copy of audit events**: devices report operation audit records
   (**metadata** such as action/resource type/success or failure/timestamps —
   no credential names, no ciphertext, no plaintext keys) in batches, and the
   server keeps a copy for later querying. The local audit database remains the
   source of record; reporting is best-effort replication (losing connectivity
   loses no local records, only the continuity of the off-site copy).
2. **Whole-database encrypted backup custody**: `persona backup push` uploads
   a full-database snapshot (VACUUM INTO → gzip → PERSENC1 encryption); the
   server sees only ciphertext, and `list/pull/restore/delete` manage the
   versions. The desktop app exposes the same capability under Settings →
   Backup → "Server ciphertext store" (push/version list/restore/delete; the
   snapshot is encrypted locally before it ever leaves the machine; the backup
   passphrase and master password never leave the machine; the entry point is
   unavailable when no server is configured — off by default, enabled
   explicitly).

### What You Don't Get

- **Server-side merge/adjudication**: merging (LWW) and conflict adjudication
  for credential sync happen entirely on the client; the server only relays
  ciphertext oplogs (see the next section). Triggering remains manual — the
  Settings page's "Sync now", not millisecond-level push.
- **Server-side tamper protection**: the server operator (that is, you, or
  whoever compromises it) can withhold, delete, or roll back backups and sync
  logs, and clients perform no freshness checks (THREAT_MODEL explicitly
  makes no claims for "backup custody endpoint" or "E2EE sync relay").

### Deploying the Server

The `persona-server` crate (axum); all configuration goes through environment
variables:

| Variable                               | Default               | Description                                                                                                                                                                                              |
| -------------------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PERSONA_SERVER_HOST`                  | `0.0.0.0`             | Listen address (use `127.0.0.1` for local experiments)                                                                                                                                                   |
| `PERSONA_SERVER_PORT`                  | `3000`                | Listen port                                                                                                                                                                                              |
| `PERSONA_SERVER_DB`                    | `./persona-server.db` | The server's own metadata database                                                                                                                                                                       |
| `PERSONA_SERVER_TOKENS`                | —                     | **Multi-device tokens**: `"laptop:tok1,phone:tok2"`; an invalid format fails at startup                                                                                                                  |
| `PERSONA_SERVER_TOKEN`                 | —                     | Legacy single token (treated as the "default" device); migrating to TOKENS is recommended                                                                                                                |
| `PERSONA_SERVER_BACKUP_DIR`            | `<DB dir>/backups`    | Directory where backup ciphertext is stored                                                                                                                                                              |
| `PERSONA_SERVER_BACKUP_MAX_VERSIONS`   | `0` (no limit)        | Per-device cap on retained versions; oldest deleted beyond the cap                                                                                                                                       |
| `PERSONA_SERVER_OPS_RETENTION_DAYS`    | `0` (no cleanup)      | Retention days for sync relay logs. Opening a window = giving up the responsibility to replay history to devices offline longer than the window; **must be ≥ the offline period of your slowest device** |
| `PERSONA_SERVER_EVENTS_RETENTION_DAYS` | `0` (no cleanup)      | Retention days for the audit-event copy; set per your SIEM ingestion cycle                                                                                                                               |

**Fail-closed**: when neither `TOKENS` nor `TOKEN` is configured, `/api/v1` is
disabled as a whole (not left wide open).

HTTP endpoints (all except health/metrics require a Bearer token):

| Endpoint              | Method              | Purpose                                                                                                                                  | Request limit                                  |
| --------------------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| `/api/v1/events`      | POST                | Report a batch of audit events (≤500 entries per batch)                                                                                  | 1 MiB on the wire (gzip) / 10 MiB decompressed |
| `/api/v1/events`      | GET                 | Query stored events (filter by action/success or failure/time + cursor pagination)                                                       | —                                              |
| `/api/v1/backups`     | POST / GET          | Upload a backup / list versions                                                                                                          | 256 MiB                                        |
| `/api/v1/backups/:id` | GET / DELETE        | Download / delete a specific version                                                                                                     | —                                              |
| `/api/v1/sync/*`      | POST / GET / DELETE | Device registration, group-key envelope fetch/upload, oplog push/pull (the transport surface for the E2EE sync section in this document) | —                                              |
| `/api/v1/auth/*`      | POST                | Device SRP authentication (register/challenge/verify exchanged for a short-lived token)                                                  | —                                              |
| `/api/v1/accounts/*`  | POST / GET / DELETE | Account domain (SRP password, passkey ceremonies, recovery codes, account devices/sessions)                                              | 1 MiB on the wire                              |
| `/api/v1/pairing/*`   | POST / GET / DELETE | Sync-group one-time-passcode pairing mailbox (**no Bearer required**, TTL 600s, queue ≤4, payload ≤4KiB)                                 | 4 KiB                                          |
| `/health`, `/metrics` | GET                 | Liveness and metrics                                                                                                                     | Public                                         |

Device names are derived from the matched token (clients cannot self-report
them); a push from the same device with the same sha256 as the latest version
is deduplicated idempotently. For endpoint details see the endpoint quick
reference in `SELF_HOST_SERVER.md`.

### Configuring the Client

**Desktop app** (Settings → Sync): enter the server URL + device token and
flip the switch on. The token's real value lives in the OS keychain (service
`persona-sync`); the database only holds an empty placeholder — copying
`identities.db` to another machine does not carry the token with it, so it
must be re-entered. Disabling sync clears the keychain entry.

**CLI**: honors environment variables only and **deliberately persists
nothing** —

```bash
export PERSONA_SERVER_URL="https://your-server:8443"
export PERSONA_SERVER_TOKEN="tok1"          # matches one entry in the server's TOKENS
export PERSONA_PAYLOAD_PASSPHRASE="..."     # backup passphrase (interactive input works too)
persona backup push
```

The two channels are **independent of each other**: the desktop Settings page's
sync configuration drives both event reporting and E2EE sync (the
Settings → Sync `sync_now` and the sync management commands share this one
URL + token), while the CLI's backup commands only read their own env. To use
one server from both the desktop app and the CLI, configure each side once.

## End-to-End Encrypted Credential Sync (Multi-Device)

On top of Mode Two, the desktop app provides **credential-level end-to-end
encrypted sync**: each device generates its own key pair (private key in the OS
keychain, service `persona-device`); after the first device creates the group
key, the remaining devices join when an already-authorized device "authorizes"
them. The group key only ever transits the server in envelope form that "only
the target device's private key can open" — **the server never sees the group
key or any plaintext**; it only relays ciphertext oplogs.

### What It Syncs

- **Credentials** (metadata plus the payload as a whole): additions, edits,
  and deletions converge across devices, and deletions propagate as
  tombstone records. Credentials that already existed **before** you joined
  sync are pushed in automatically on the next sync run.
- Sync is **triggered manually**: Settings → End-to-End Encrypted Sync →
  "Sync Now" runs one pass of "pull → apply → push". With both devices
  online, a single pass is enough to converge; local changes are journaled
  first and pushed automatically once the device is back online.

### How Devices Join (Current and Planned)

- **Current (implemented)**: the first device bootstraps the group → the
  second device taps "Join Sync" and shows a pending-authorization badge →
  an already-authorized device taps "Authorize". See the two-device
  walkthrough below.
- **Implemented (S1 desktop wiring)**: dynamic-password pairing for a sync
  group — one side displays a 9-digit short-lived dynamic password, the
  other side types it in, and the two exchange the group key over PAKE to
  complete the join, then compare a 6-digit short fingerprint on both sides
  to guard against man-in-the-middle, with no account anywhere in the flow
  (`docs/sync-group-mode.md`). The protocol core, the account-free relay
  mailbox, and the relaying client are implemented (`core/src/sync/pairing.rs`,
  server `/api/v1/pairing/*`); the desktop settings page wires up the
  display-code, enter-code, fingerprint-comparison, and join UI
  (`desktop/src/components/SyncGroupSection.tsx` plus seven `sync_group_*`
  commands in `desktop/src-tauri/src/commands.rs`).

### What It Does Not Sync (Honest Boundaries)

- **Identity rows are not synced** — credentials and passkeys are; identity
  rows are still created locally on each device, and when materialization
  hits a missing identity it parks the work as `pending_identity` until the
  row is filled in.
- **A passkey's device-local usage state is not synced** — `sign_count` /
  `last_used_at` advance independently on each device (copying counters
  across devices would forge the baseline that WebAuthn clone detection
  depends on); what syncs is the registration-semantic fields (rp,
  credential id, private key envelope, COSE public key, algorithm, UV /
  exportable flags, label), with the private key envelope carried over
  as-is (the item key travels inside the group envelope and is re-wrapped
  under the local master key, byte-for-byte identical, so it still decrypts
  as usual).
- **Attachment file bodies are not synced.**
- **Local audit, app settings, and the master password hierarchy stay out
  of sync** — each device's master password is independent of the others
  (they may differ), changing the master password affects only that device,
  and it has zero effect on sync.
- Conflict adjudication is an **all-or-nothing choice**: whichever version
  you adopt is adopted whole; there is no field-level merge.

### How Conflicts Are Adjudicated

Most of the time there is no conflict: concurrent edits are ordered
automatically by operation version number (Lamport clock), and the newer one
wins. Real conflicts only show up when "two devices both offline edited the
**same** credential at the same edit round" — at that point both versions
are kept (no data loss, no silent overwrite), and once the sync finishes an
amber banner appears in settings; "View Conflicts" opens an adjudication
dialog with the two versions side by side, and adopting one is all it takes
(the other versions stop appearing).

The local oplog **prunes itself automatically**: at the end of every sync,
old operations already superseded by a newer version, and deletion records
past their 30-day retention window, are cleaned up — unpushed changes,
unadjudicated conflict versions, and the currently effective version are
kept forever. Append-only means nothing is overwritten and nothing is
silently modified; it does not promise to retain every historical version
forever.

### What the Server Can See

Ciphertext, item UUIDs, operation types, version numbers, timestamps, device
public keys, and envelopes. **Item sizes are observable** (a size side
channel, honestly registered in THREAT_MODEL). The server can withhold,
delete, or roll back the log (no tamper-resistance is claimed), but it
cannot read any of the content; while "Travel Mode" is active, sync pauses
outright (both push and pull stop), and identities that were moved out are
never written back.

### Getting Started: Joining and Authorizing

1. Deploy a server (same as Mode Two; `/api/v1/sync/*` needs no extra
   configuration and reuses the same device token).
2. Desktop app → Settings → End-to-End Encrypted Sync: enter a device name →
   "Join Sync". **On a brand-new server the first device creates the group**
   (bootstrap), so joining is also authorizing.
3. The second device taps "Join Sync" the same way → a "Pending
   Authorization" badge appears; go back to an authorized device's device
   list and tap "Authorize" on it.
4. Tap "Sync Now" once on each; credentials start converging.

### Two-Device Walkthrough

Ready to run as-is (two devices = two environments with the Persona desktop
app installed, sharing one server and token):

1. **Device A joins**: Settings → End-to-End Encrypted Sync → device name
   `laptop` → Join. On a brand-new server A bootstraps the group, the status
   line reads "Joined: laptop", and there is no pending-authorization badge.
2. **Device B joins**: join the same way with the name `phone` → a prompt
   says "Registered — authorize this device on another already-authorized
   device"; in the device list, `phone` carries a "Pending Authorization"
   badge.
3. **A authorizes B**: A's device list → the `phone` row → "Authorize" → a
   confirmation appears, and the pending-authorization badge on the `phone`
   row disappears.
4. **A creates a credential → A taps "Sync Now"**: a sync-complete message
   appears (several entries are pushed — the pre-existing credentials are
   pushed in on the first run).
5. **B taps "Sync Now"** (pulling the same number of entries) → the same
   credential shows up in B's credential list.
6. **Offline conflict**: disconnect both devices from the server (or simply
   stop the server), have A and B each edit the **same** credential (say A
   changes the username and B changes the URL) → bring the server back →
   tap "Sync Now" on both → at least one device shows an amber banner
   saying "N entries have conflict versions from concurrent edits" → tap
   "View Conflicts" to open the adjudication dialog: one version is labeled
   "Current version", the other "Content differs".
7. **Adjudication**: tap "Adopt this version" on one of them → a message says
   "Selected version adopted", and that entry disappears from the dialog;
   after the other device taps "Sync Now" again, both converge on the same
   version.
8. **(Optional) Revoke**: A's device list → `phone` → "Revoke" → `phone`
   immediately loses its sync eligibility (later sync attempts are refused
   by the server); the data in `phone`'s own vault is unaffected (the main
   database's ciphertext belongs to the master password hierarchy). If after
   revoking you also need `phone` to be unable to read the sync history,
   see the next section, "Rotating the Group Key".

> Known boundary: if two devices join an empty group one after the other
> within the very short window where "neither has joined yet", each may
> create its own group (concurrent bootstrap) — this shows up as neither
> device seeing the other's entries. Have one side "Leave Sync" and join
> again, and the normal flow is back.

### Rotating the Group Key

After you revoke a device, the group key it knew before removal can still
open the sync history (a group key cannot be retroactively revoked) —
**rotation** is what actually closes the loop: Settings → End-to-End
Encrypted Sync → "Rotate Group Key". Rotation = generate a new group key,
re-envelope it for every device that is **still authorized**, and re-encrypt
and re-record every credential under the new key; from then on the old key
held by a revoked device opens none of the new ciphertext. Rotation is also
recommended when you suspect a device's key has leaked, or when you want to
expel a member who has left from the history entirely.

Three honest boundaries (the confirmation dialog says the same):

- **Tap "Sync Now" on every device first**: rotation only re-wraps the
  entries that have been pushed at that moment; changes still sitting
  unpushed on other devices were recorded under the old key, and only
  devices holding the new envelope will fail to open them (the local data
  itself is unaffected).
- **Unadjudicated conflict copies** are cleared out of the adjudication
  view by a rotation (the main database's current state wins; the oplog is
  append-only, so the original records remain).
- **Two devices rotating at the same time are mutually excluded by an
  optimistic lock** (2026-09-24): before rotation begins, the mutex is
  claimed on the server with an epoch optimistic lock (`rotate-begin`), and
  whichever side arrives second aborts cleanly with a `CONCURRENT_CONFLICT`
  error — no envelopes written, nothing re-wrapped; re-read the state and
  retry and you are fine. This only guards against accidental concurrency
  from honest clients, not against a malicious client routing around it
  (see THREAT_MODEL for the write-authenticity boundary).

## Backup and Restore in Practice

> The backup and restore channels run in parallel — the CLI (the five
> `persona backup` commands in the table below) and the desktop settings
> page's BackupSection (`desktop/src/components/BackupSection.tsx`, six
> `backup_*` commands in `desktop/src-tauri/src/commands.rs`). The "Sync"
> switch in desktop settings drives both event reporting and end-to-end
> sync.

| Command                                 | What it does                                                                          |
| --------------------------------------- | ------------------------------------------------------------------------------------- |
| `persona backup push`                   | Snapshot the current vault → encrypt → upload (no need to unlock the master password) |
| `persona backup list`                   | List versions (newest → oldest, paginated)                                            |
| `persona backup pull <id> --out f`      | Download the ciphertext to a file (does not decrypt)                                  |
| `persona backup restore <id>\|--file f` | Decrypt and verify → keep a `.bak` → swap in the database                             |
| `persona backup delete <id>`            | Delete the version on the server                                                      |

Key points:

- **The backup passphrase and the master password are independent of each
  other**. Restore = download the ciphertext + decrypt it with the backup
  passphrase + unlock with the master password. Lose the backup passphrase
  and that backup is permanently unrecoverable (no escrow, no reset).
- push sets up a double-entry confirmation, restore does not (the passphrase
  already exists); restore automatically copies the current vault to
  `identities.bak` first.
- **Attachment file bodies are not in a v1 backup**: after a restore the
  attachment metadata is there but the file bodies are missing (the CLI
  and the desktop app both state this limitation explicitly).
- A backup is a snapshot, not an increment: a restore takes the whole vault
  back to the moment of the backup.

## Cloud Drive Folders (iCloud / Dropbox / WebDAV…)

⚠️ **Do not put a live `identities.db` in a cloud drive's sync folder**.
SQLite assumes it has exclusive write access to the file, and a cloud
drive's bidirectional sync produces conflict copies and a real risk of
corruption — this is the most common way people shoot themselves in the
foot here.

The right way: the cloud drive holds **encrypted artifacts only** —

- the export file from `persona export --encrypt`, or
- the `.persenc` backup ciphertext downloaded by `persona backup pull`.

Both carry an independent passphrase, so the cloud provider only ever sees
ciphertext. The price is having to run this yourself by hand (or on a
timer, via a script), and that a restore is whole-vault.

(A "file-system sync adapter" — a local service that watches for changes and
pushes/pulls encrypted blobs automatically — is a future item in
[the design draft](./CLIENT_COMMUNICATION_ARCHITECTURE.md); it is not
implemented today.)

## Multiple Devices and Travel Mode

- Each device runs its own `init` and forms its own independent vault. There
  are now three ways to collaborate across devices: **credential-level E2EE
  sync** (see the dedicated section above; incremental, converges
  automatically), a **backup version pool + whole-vault restore** (each
  device pushes with its own token and versions are grouped by device;
  whole-vault snapshots, manual), and **cold backup via a cloud drive**
  (manually copying encrypted artifacts).
- Restoring one device's vault from another device's backup is a **whole-vault
  replacement** (the existing data is swapped out to `.bak`), not a merge;
  if you need incremental consistency, use credential sync.
- [`Travel Mode`](./THREAT_MODEL.md#travel-mode-travelpersenc-sidecar-2026-09)
  (`persona travel …` / desktop settings general page → Safe Zone) exists to
  temporarily move whole identities **out of** one device (an encrypted
  sidecar travels with you), and a passphrase restores them when you come
  back — in a multi-device setup it is the tool for bounding how much one
  device can expose. While Travel is active, credential sync pauses
  outright (both push and pull stop), which prevents pushing the tombstones
  of moved-out identities to other devices, or pulling already-moved-out
  identities back into this vault.

## Local Automation (Connect API)

An HTTP interface that lets local scripts / CI / command-line tools read
vault entries **read-only**. Off by default; once enabled it listens only on
`127.0.0.1` (on a system-assigned port), and requests never leave the
machine. See
[`CONNECT_AUTOMATION_DESIGN.md`](./CONNECT_AUTOMATION_DESIGN.md) and
[THREAT_MODEL](./THREAT_MODEL.md#connect-local-automation-endpoint-127001-http-2026-09-secrets-automation)
for details. **The guide for integrating an external project (three steps +
measured response samples + token expiry/revocation semantics + permission
boundaries) is in
[`EXTERNAL_INTEGRATION.md`](./EXTERNAL_INTEGRATION.md).**

**Two steps to start using it:**

1. Create a token (the plaintext is shown only once; if you lose it you can
   only revoke and recreate it):

   ```bash
   # Desktop: settings general page → Connect local automation → Create Token
   # CLI (by default authorizes every authorizable type on every identity, read-only):
   persona connect token create --label "my CI script"
   # Narrow the scope (a restricted set narrows it; the default = everything):
   persona connect token create --label "deploy" --identity work --type password --type api_key
   ```

2. Start the listener (foreground process, Ctrl-C to exit; the desktop app
   toggles it in settings):

   ```bash
   persona connect serve            # or --port 8737 for a fixed port
   ```

**curl quick start** (`$TOKEN` is the `pconn_…` plaintext you saved at
creation time; see the serve startup output for `$PORT`):

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:$PORT/api/v1/connect/health
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:$PORT/api/v1/connect/identities
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:$PORT/api/v1/connect/items
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:$PORT/api/v1/connect/items/<id>/totp
```

Boundaries (honest version):

- **Read-only**. There is no write path; scope can only be narrowed, never
  elevated; passkey / wallet / SSH key / custom types can **never** be
  authorized through this interface.
- Tokens are stored only as SHA-256 hashes, so listings show just a
  fingerprint; `persona connect token revoke` (accepts an id or a
  fingerprint) takes effect immediately and is idempotent.
- Rate limit 120 requests/minute; a locked vault returns 503 (locking does
  not consume your quota).
- This defense line only covers local browser-side attacks (a malicious web
  page) — **do not** hand the token to a browser extension or to any
  web-reachable store; a malicious local process was already outside the
  trust boundary to begin with.

## Secrets Automation (Direct CLI Read)

The Connect API serves **cross-process** consumers (HTTP clients), while
`persona secrets` is the **same-process** direct CLI read path, handing
plaintext to scripts / CI / declarative tools across three bundles: shell
plugins (env injection + subprocess execution), Kubernetes Secret manifest
rendering, and the Terraform `external` provider protocol.

The **reference syntax** is uniformly `IDENTITY/ITEM/FIELD` (identities
matched by name, items by credential name, exact match; a duplicate name is
an error, never a guess):

- `name` / `username` / `url` / `notes` read metadata and **do not
  decrypt**;
- every other field is read per the field vocabulary of its item type
  (`persona secrets` lists the legal fields in the error message), and an
  unset optional field is an error — it **never silently returns an empty
  string**;
- `secret` is an alias for each type's primary secret (Password→`password`,
  API Key→`api_key`, TOTP→`secret_key`, SSH Key→`private_key`,
  Server→`password`, Secure Note→`note`, wallet→`private_key`,
  License→`license_key`).

Every decryption goes through the same audit path as desktop and CLI
display (`CredentialDecrypted`), which trips the auto-lock timer.

**The four subcommands:**

```bash
# 1. resolve: scripting primitive, one value per line (same order as the arguments)
export API_KEY="$(persona secrets resolve work/deploy/api_key)"

# 2. run: inject plaintext into the subprocess environment, then execute
#    (never enters shell history, never touches disk)
persona secrets run --env GITHUB_TOKEN=work/ci/api_key -- gh repo view

# 3. k8s: render a Secret manifest (data base64-encoded) to stdout for kubectl apply to consume
persona secrets k8s --name deploy-secrets --namespace prod \
  --key password=work/deploy/password --key token=work/ci/api_key \
  --label app.kubernetes.io/managed-by=persona | kubectl apply -f -

# 4. external: helper for the Terraform external provider protocol
#    (stdin JSON query → stdout JSON plaintext; the native gRPC provider
#    would need the Go SDK, deliberately not done)
```

```hcl
data "external" "persona" {
  program = ["persona", "secrets", "external"]
  query = { db_password = "work/db/password" }
}
```

Boundaries (honest version):

- **Read-only**; it shares the unlock chain with Connect (it prompts for the
  master password when there is no unlocked session). Setting
  `PERSONA_WORKSPACE_PATH` + `PERSONA_MASTER_PASSWORD` makes the whole flow
  non-interactive in CI (see
  [NON_INTERACTIVE_MODE](./NON_INTERACTIVE_MODE.md)).
- Plaintext is delivered via stdout / environment variables — redirecting
  `resolve` output to disk or echoing it into CI logs is the caller's
  responsibility; `run`'s injection exists only in the subprocess
  environment.
- Card types have no `secret` alias (a card number and a CVV have no single
  "primary secret"); reference them by their specific fields.

## Failure Consequences at a Glance

| Scenario                               | Consequence                                                                                                                                      | Recoverable                                                                                                  |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Master password lost                   | Every credential in the vault becomes undecryptable                                                                                              | No (no escrow, no reset)                                                                                     |
| Backup passphrase lost                 | That backup cannot be restored                                                                                                                   | No (other versions are unaffected)                                                                           |
| Identity/credential deleted by mistake | Deleted locally                                                                                                                                  | Yes — restore the whole vault to an older backup (everything after that snapshot point is lost)              |
| `identities.db` corrupted              | The local vault is unusable                                                                                                                      | Yes — restore, but **all changes after the last push are lost**                                              |
| Server data deleted/rolled back        | The backup version pool is damaged; a rolled-back sync log loses "pushed but not yet pulled" propagation (each side's local vault is unaffected) | No — no protection against the server operator is claimed; the local vault remains the first source of truth |
| Travel sidecar lost                    | The moved-out identities are lost permanently                                                                                                    | No (the red-warning scenario in THREAT_MODEL's "Travel Mode")                                                |

The principle in one sentence: **the local vault is the first source of
truth, and every backup mechanism is just one more copy of the ciphertext
kept elsewhere** — make "push/export regularly" a habit and leave the rest to
the honest boundaries in the threat model.
