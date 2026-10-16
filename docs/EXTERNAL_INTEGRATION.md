# External project integration with Persona (External Integration)

> [English](EXTERNAL_INTEGRATION.md) | [中文](EXTERNAL_INTEGRATION.zh.md)

> **Status: current state (verified live on 2026-10-12)**. Every JSON snippet
> and output in this document comes from a real smoke run (isolated workspace +
> `persona connect serve` + curl), not hand-written illustration. For the design
> background see
> [`CONNECT_AUTOMATION_DESIGN.md`](./CONNECT_AUTOMATION_DESIGN.md); for a short
> quick-reference see
> [`STORAGE_AND_SYNC.md`](./STORAGE_AND_SYNC.md#local-automation-connect-api).

External projects (CI scripts, deploy tools, other local services) read the
Persona vault through exactly one of **two supported interface forms**:

| Form                        | Best for                                                                                                                                                                                                    | Depends on                                |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| **HTTP (Connect API)**      | Cross-process consumers: CI, background services, programs in any language                                                                                                                                  | `persona connect serve` listening + token |
| **CLI (`persona secrets`)** | Shell scripts, Makefiles, Terraform/K8s declarative tooling                                                                                                                                                 | Only the persona CLI on PATH              |
| ~~Library linkage~~         | **Not recommended**: the core crate has no stable API or version promise, and it requires the consumer process to hold the master password in order to unlock — equivalent to handing over the entire vault | —                                         |

The authorization model is identical for both forms: enforcement happens at the
single adjudication point `authorize(principal, resource, action, ctx)` in
`core/src/authz.rs` (verbs `read/use/export/sign`; a Connect token principal can
only be granted `read/use`, and only `read` is exposed over HTTP). export (bulk
plaintext export) and sign (SSH signing) can **never be granted** to a token
principal.

---

## Three-step integration (HTTP form)

### Step 1: issue a token (vault owner action, one-time)

```bash
persona connect token create --label "other-project" \
  --identity ci-project --type password --type totp --expires-in 30d
```

Actual output (the plaintext `pconn_…` is **shown only this once** — if you lose
it, you can only revoke and re-create):

```
🔑 Connect token created
pconn_C-LUE7XcPUhlPMdbh6v7Rx_Z6GzrbDqRDqx_DN_1Yrg
⚠️  Copy it now — the plaintext is shown only once and cannot be recovered.
   label:      other-project
   id:         20a19e6d-9d42-4851-b2e7-d8da03f9049b
   fingerprint: 4b322627054123fd
   scope:      1 identity · password,totp · read-only
   expires at: 2026-11-11T15:09:47.568039674+00:00
```

**Token issuance and expiry semantics:**

- Only the **SHA-256 hash** is stored; lists and logs show just a 16-hex
  fingerprint, and the plaintext cannot be recovered.
- `--expires-in <N><s|m|h|d>`: the lifetime relative to the current time (e.g.
  `30d`, `12h`, `30m`, `45s`). **Omitted = never expires** — for tokens given
  to external projects, setting it is strongly recommended.
- The argument is parsed **before** master-password unlock: a wrong unit, a
  negative number, or a compound form like `1h30m` fails immediately with
  `Error: invalid duration "1h30m": unknown unit "h30m" (valid: s, m, h, d)`
  and never triggers a passphrase prompt.
- Requests are rejected once expired: after `expires_at` the request gets a 401
  **identical in shape** to an unknown token (verified: `--expires-in 1s`, curl
  three seconds later → 401 `invalid token`).
- Revocation (takes effect immediately, idempotent; accepts **id (UUID) or
  fingerprint (hex)**, never the plaintext):

  ```bash
  persona connect token revoke 20a19e6d-9d42-4851-b2e7-d8da03f9049b   # or 4b322627054123fd
  ```

  Verified: a successful revoke prints
  `✓ Token 67474c13-3496-4f71-a08c-1dc01644b2b7 revoked`, and requests with
  that token get a 401 immediately afterwards.

- `persona connect token list` status column: `active` (green) / `revoked` (red)
  / `expired` (yellow, computed from `expires_at`), with `never used` /
  `last used …` / `revoked at …` and `expires at …` lines.

### Step 2: start the listener (local background, one-time)

```bash
persona connect serve --port 8737        # default --port 0 lets the OS assign; Ctrl-C to exit
```

- Listens only on `127.0.0.1`; requests never leave the machine; the vault must
  be unlocked — in a foreground terminal use `--passphrase-env <VAR>` to specify
  which environment variable to read (it must already be set and non-empty), and
  the desktop app toggles this in Settings. For the full non-interactive unlock
  story see [`NON_INTERACTIVE_MODE.md`](./NON_INTERACTIVE_MODE.md).
- The listener process is decoupled from the consumer process: token validation
  happens per request, and a locked vault returns 503 (see the error code table).

### Step 3: call it (consumer side, any HTTP client)

```bash
TOKEN=pconn_C-LUE7XcPUhlPMdbh6v7Rx_Z6GzrbDqRDqx_DN_1Yrg   # saved in step 1
B=http://127.0.0.1:8737/api/v1/connect

curl -s -H "Authorization: Bearer $TOKEN" $B/health
curl -s -H "Authorization: Bearer $TOKEN" $B/identities
curl -s -H "Authorization: Bearer $TOKEN" $B/items
curl -s -H "Authorization: Bearer $TOKEN" $B/items/<id>
curl -s -X POST -H "Authorization: Bearer $TOKEN" $B/items/<id>/totp
```

**That's all.** There is no registration, no handshake, and no required SDK
beyond the token.

---

## Endpoint reference (verified responses)

Every response carries `content-type: application/json` and
`cache-control: no-store`; success envelopes look like `{"ok":true,"data":…}`,
error envelopes like `{"ok":false,"error":{"code","message"}}`.

### `GET /health` — unauthenticated liveness probe

```json
{ "data": { "service": "persona-connect", "version": "0.1.0" }, "ok": true }
```

Carries no vault information; provided for listener health probing.

### `GET /identities` — identities in scope

```json
{
  "data": [
    { "id": "b5b6b785-08a1-4d30-85cc-b5854915af3e", "name": "ci-project" }
  ],
  "ok": true
}
```

### `GET /items` — items in scope (metadata only)

```json
{
  "data": [
    {
      "id": "d4ac3439-c311-4454-ac49-a669c0034a9e",
      "title": "Deploy dashboard 2FA",
      "type": "totp",
      "updated_at": "2026-10-12T15:09:40.314861814+00:00",
      "urls": []
    },
    {
      "id": "134a2c8e-e129-486e-8b09-31b85eefc954",
      "title": "Deploy dashboard login",
      "type": "password",
      "updated_at": "2026-10-12T15:09:18.610407644+00:00",
      "urls": ["https://dash.example.com/login"]
    }
  ],
  "ok": true
}
```

`type` is snake_case. The list contains **no** secret fields.

### `GET /items/{id}` — item detail (with the decrypted secret)

```json
{
  "data": {
    "data": {
      "Password": {
        "email": null,
        "password": "smoke-secret-9f8e7d6c",
        "security_questions": []
      }
    },
    "id": "134a2c8e-e129-486e-8b09-31b85eefc954",
    "title": "Deploy dashboard login",
    "type": "password",
    "updated_at": "2026-10-12T15:09:18.610407644+00:00",
    "urls": ["https://dash.example.com/login"],
    "username": "deploy-bot"
  },
  "ok": true
}
```

Note that the field names inside `data` are **PascalCase** (`Password` /
`ApiKey` / …, serde's default externally tagged representation, no rename_all) —
consumers parsing it should take the key matching the item's type.

### `POST /items/{id}/totp` — compute a TOTP code on demand

```json
{ "data": { "code": "539466", "remaining_seconds": 8 }, "ok": true }
```

---

## Authorization boundaries (what a token can and can never get)

**Three-dimensional scope**: identities × item_types × verbs. At `create` time
the rule is "omitted = the full legal set; providing a restriction narrows it".
Items outside the scope and nonexistent items return the **same 404 shape**
(verified: a password-only token reading a totp item → `not_found`,
indistinguishable from a fabricated id), so existence is never leaked.

| Boundary           | Semantics                                                                                                                                                                                                                            |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| verbs              | Only `read` can be granted and HTTP exposes only `read`; `use` is already in the authorization model but **has no consumer endpoint yet** (reserved, do not rely on it); `export` / `sign` can never be granted to a token principal |
| Excluded types     | ssh-key / crypto-wallet / custom can **never be authorized** (they are not in the authorizable type set); passkeys do not go through this endpoint (they use a separate Unix socket approval channel)                                |
| Authorizable types | password / api_key / totp / note / bank_card / server_config / certificate / game_account / identity / software_license                                                                                                              |
| Network surface    | Listens only on `127.0.0.1`; a `Host` header other than `127.0.0.1`/`localhost` → 421; a request carrying an `Origin` header (browser-originated) → 403                                                                              |
| Rate               | 120 requests/minute per token (fixed window); exceeding it → 429                                                                                                                                                                     |
| Locking            | Locked vault → 503 `vault_locked`, does not consume the rate limit                                                                                                                                                                   |
| Auditing           | Every token validation/rejection leaves an audit record; the decryption path is the same one the desktop/CLI display uses                                                                                                            |

## Error code table (verified shapes)

| HTTP | code               | Verified message                              | Trigger                                                          |
| ---- | ------------------ | --------------------------------------------- | ---------------------------------------------------------------- |
| 401  | `unauthorized`     | `missing or malformed bearer token`           | Missing or malformed Authorization header                        |
| 401  | `unauthorized`     | `invalid token`                               | Unknown, revoked, or expired token (all three indistinguishable) |
| 403  | `origin_forbidden` | `browser-originated requests are not allowed` | Request carries an `Origin` header                               |
| 404  | `not_found`        | `item not found`                              | Item does not exist / is archived / out of scope (same shape)    |
| 421  | `bad_host`         | `host not allowed`                            | `Host` header other than `127.0.0.1`/`localhost`                 |
| 429  | `rate_limited`     | —                                             | More than 120 req/min                                            |
| 503  | `vault_locked`     | —                                             | Vault locked (does not consume the rate limit)                   |

Retry discipline: never retry a 401 (deterministic rejection — go check
revocation/expiry); 503 can be retried with backoff (waiting for the owner to
unlock); 429 backs off per minute window.

## Consumer-side guidance (Do / Don't)

- **Must do**: treat the token like a password — inject it via environment
  variables or a secret manager; never commit it to git, never log it, and never
  put it in any browser/web-reachable storage (the `Origin` 403 guards against
  malicious web pages, it is not a turnkey license).
- **Must do**: set `--expires-in` to your rotation period; re-issue once it
  expires.
- **Recommended**: minimize scope — grant only the identities and types you
  need (e.g. deploy only needs `--type password`).
- **Don't**: hand the token to a browser extension or forward it to a remote
  machine (the interface only serves this machine).
- **Don't**: integrate via "library linkage" outside the HTTP form — the core
  crate makes no stable API promise, and in-process unlocking is equivalent to
  handing the entire vault to the consumer process.

## Forms outside these boundaries

- **`persona secrets` (direct CLI reads)**: use this when same-machine shell/CI
  would rather not stand up HTTP. The reference syntax is
  `IDENTITY/ITEM/FIELD`; for the four subcommands (run / resolve / k8s /
  terraform-external) see
  [`STORAGE_AND_SYNC.md`](./STORAGE_AND_SYNC.md#secrets-automation-direct-cli-read).
- **Remote persona-server**: cross-machine reads belong to the **E2EE sync
  client** world ([`E2EE_SYNC_DESIGN.md`](./E2EE_SYNC_DESIGN.md) /
  [`REMOTE_AUTH.md`](./REMOTE_AUTH.md)), not plain REST — the Connect API's
  token/endpoint model does **not** apply remotely; do not mix the two.
- **Browser extensions**: they go through the Native Messaging Host bridge
  ([`BRIDGE_PROTOCOL.md`](./BRIDGE_PROTOCOL.md)) and do **not** pass through the
  Connect API.

## Open questions (honest version)

- No HTTP consumer endpoint for the `use` verb is implemented (the
  authorization model reserves it); the write path is not decided, so the
  current interface is **read-only**.
- The desktop app's token-creation entry point does not yet pass an
  `--expires-in` equivalent (tokens never expire); external projects should
  issue tokens via the CLI.
