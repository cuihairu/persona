# Persona Bridge Protocol v2

> [English](BRIDGE_PROTOCOL.md) | [中文](BRIDGE_PROTOCOL.zh.md)

The Persona Native Messaging Bridge Protocol defines secure communication between the browser extension and the local CLI/Desktop.

## Overview

The browser extension communicates with the locally running `persona bridge` process through the Chrome Native Messaging API. The protocol supports:

- Status queries (locked/unlocked state)
- Autofill suggestion retrieval
- Credential fill requests
- TOTP code retrieval
- Passkey (WebAuthn) create / assert / list (added in v2)
- Session management

## Transport Layer

### Native Messaging frame format

Follows the Chrome Native Messaging standard:

```
[4 bytes: little-endian length][JSON payload]
```

- The length field is a 32-bit unsigned integer (little-endian)
- Maximum message size: 10MB (hard limit; exceeding it returns `invalid_frame_length`)
- Encoding: UTF-8 JSON

## Message Structure

### Request format

```json
{
  "request_id": "uuid-v4",
  "type": "message_type",
  "payload": { ... },
  "auth": { ... }
}
```

| Field        | Type   | Required | Description                                                            |
| ------------ | ------ | -------- | ---------------------------------------------------------------------- |
| `request_id` | string | No       | Unique ID used to correlate request/response                           |
| `type`       | string | Yes      | Message type                                                           |
| `payload`    | object | No       | Type-specific payload data                                             |
| `auth`       | object | No       | Message authentication (required for sensitive operations once paired) |

#### auth field (HMAC)

```json
{
  "session_id": "uuid-v4",
  "ts_ms": 1734660000000,
  "nonce": "uuid-v4",
  "signature": "base64url-no-pad"
}
```

| Field        | Type   | Required | Description                                                           |
| ------------ | ------ | -------- | --------------------------------------------------------------------- |
| `session_id` | string | Yes      | Short-lived session ID issued by `hello_response`                     |
| `ts_ms`      | number | Yes      | Client timestamp (milliseconds); bounds the server-side replay window |
| `nonce`      | string | Yes      | Per-request random value                                              |
| `signature`  | string | Yes      | `HMAC-SHA256` signature (base64url, no padding)                       |

### Response format

```json
{
  "request_id": "uuid-v4",
  "type": "response_type",
  "ok": true,
  "error": null,
  "payload": { ... }
}
```

| Field        | Type    | Required | Description                              |
| ------------ | ------- | -------- | ---------------------------------------- |
| `request_id` | string  | No       | ID of the request being answered         |
| `type`       | string  | Yes      | Response type                            |
| `ok`         | boolean | Yes      | Whether the operation succeeded          |
| `error`      | string  | No       | Error description (only when `ok=false`) |
| `payload`    | object  | No       | Response data                            |

## Message Types

### 1. hello - Handshake

Initializes the session and retrieves the server's capabilities.

**Request:**

```json
{
  "type": "hello",
  "payload": {
    "extension_id": "abcdefghijklmnopabcdefghijklmnop",
    "extension_version": "1.0.0",
    "protocol_version": 7,
    "client_instance_id": "uuid-v4"
  }
}
```

**Response:**

```json
{
  "type": "hello_response",
  "ok": true,
  "payload": {
    "server_version": "0.1.0",
    "protocol_version": 7,
    "capabilities": [
      "status",
      "pairing_request",
      "pairing_finalize",
      "get_suggestions",
      "request_fill",
      "get_totp",
      "copy",
      "passkey_list",
      "passkey_create",
      "passkey_assert",
      "passkey_credential_provider_list",
      "passkey_credential_provider_assert",
      "find_for_save",
      "save_credential",
      "generate_password",
      "sync_connect",
      "account_login",
      "account_status",
      "account_logout",
      "sync_push_now",
      "sync_resolve_conflict"
    ],
    "pairing_required": true,
    "paired": false,
    "session_id": null,
    "session_expires_at_ms": null,
    "connect_available": false,
    "connect_port": null
  }
}
```

> Note: when pairing is already complete, `pairing_required=false` and a `session_id` is returned (short-lived session, 24h by default).
> The server returns its own supported `protocol_version` (currently 7; see the hello payload in `cli/src/commands/bridge.rs`). An extension that declares an older version receives `unknown_type` for message types it does not recognize, so older extensions keep working.
> `connect_available` / `connect_port`: the probe result for the local desktop/CLI Connect server (reads `~/.persona/connect.port` and pings `/health`, overridable via `PERSONA_CONNECT_PORT`), used for unlock integration; `false` / `null` when no server is running.

### 2. pairing_request - Request a pairing code

The extension asks the local bridge for a one-time pairing code (the user must approve it in the terminal).

**Request:**

```json
{
  "type": "pairing_request",
  "payload": {
    "extension_id": "abcdefghijklmnopabcdefghijklmnop",
    "client_instance_id": "uuid-v4"
  }
}
```

**Response:**

```json
{
  "type": "pairing_response",
  "ok": true,
  "payload": {
    "code": "123-456",
    "expires_at_ms": 1734660600000,
    "approval_command": "persona bridge --approve-code 123-456"
  }
}
```

### 3. pairing_finalize - Complete pairing

After the user runs `approval_command`, the extension submits the pairing code to finalize the binding and obtain the pairing key and session information.

**Request:**

```json
{
  "type": "pairing_finalize",
  "payload": {
    "extension_id": "abcdefghijklmnopabcdefghijklmnop",
    "client_instance_id": "uuid-v4",
    "code": "123-456"
  }
}
```

**Response:**

```json
{
  "type": "pairing_finalize_response",
  "ok": true,
  "payload": {
    "paired": true,
    "pairing_key_b64": "base64url-no-pad",
    "session_id": "uuid-v4",
    "session_expires_at_ms": 1734746400000
  }
}
```

### 4. status - Status query

Returns the current unlock state and the active identity.

**Request:**

```json
{
  "type": "status",
  "payload": {}
}
```

**Response:**

```json
{
  "type": "status_response",
  "ok": true,
  "payload": {
    "locked": false,
    "active_identity": "uuid-v4"
  }
}
```

### 5. get_suggestions - Get suggestions

Returns credential suggestions matching the current page origin.

> Note: suggestions are filtered by the current workspace's `active_identity_id` by default (switchable with `persona switch`).

**Request:**

```json
{
  "type": "get_suggestions",
  "payload": {
    "origin": "https://github.com",
    "form_type": "login",
    "host": "github.com",
    "cwd": "/home/user/projects/widgets"
  }
}
```

| Field       | Required | Description                                                                                                                             |
| ----------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `origin`    | Yes      | Page origin; the host is parsed from it for URL matching and host-mapping signals                                                       |
| `form_type` | No       | `"login"` (default) or `"card"`                                                                                                         |
| `host`      | No       | Explicit host signal (e.g. when the page fills a form on a different domain); falls back to the origin's host when omitted              |
| `cwd`       | No       | Current terminal directory (desktop bridge scenario), used for repo discovery and in-repo mapping; the browser extension never sends it |

`host`/`cwd` are both optional extensions: when omitted, behavior is identical to older versions (backwards compatible).

**Response:**

```json
{
  "type": "suggestions_response",
  "ok": true,
  "payload": {
    "suggesting_for": "github.com",
    "items": [
      {
        "item_id": "uuid-v4",
        "title": "GitHub (Work)",
        "username_hint": "user@example.com",
        "match_strength": 100,
        "credential_type": "password",
        "identity": "Work"
      }
    ],
    "context": {
      "identity": "OpenSource",
      "score": 1.0,
      "reason": "repo github.com/acme/widgets"
    }
  }
}
```

| Field              | Description                                                                                                                                                                       |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `items[].identity` | Name of the identity the credential belongs to (always present since 2026-10; the popup can use it to label entries)                                                              |
| `context`          | Identity-level suggestion from the context layer; the whole field is omitted when there are no candidates or `PERSONA_NO_CONTEXT` is set (older consumers still see the v7 shape) |

**Context awareness (since 2026-10, phase 4 bridge-half):**

- `host`/`cwd` signals are scored by the **same** core `suggest()` used by `persona suggest` (mapping chain
  `PERSONA_CONTEXT_OVERRIDE` > in-repo `.persona/context.toml` > global
  `~/.persona/context.toml` > learned > active), so every entry point yields the same candidate set.
- Credentials of the suggested identity are merged into the candidates and placed first (URL match strength
  still ranks within an identity); **suggest only, never authorize** — the active identity is not switched and
  no fill authorization gate is relaxed.
- Any mapping load failure silently degrades to no suggestion (design §10).

| match_strength | Meaning                |
| -------------- | ---------------------- |
| 100            | Exact domain match     |
| 90             | Subdomain match        |
| 80             | Domain-contains match  |
| 60             | Top-level domain match |

**`form_type` parameter (since 2026-09):**

- `"login"` (default; falls back to it when omitted): returns password/totp suggestions filtered by URL match strength.
- `"card"`: returns **all active BankCards** of the current workspace with no URL filtering
  (a card has no canonical home site, and checkout pages vary by merchant); `match_strength` is always 100,
  `credential_type` is `"bank_card"`, `username_hint` is `null`; the user picks one in the popup.
  Cards of the context-suggested identity are likewise merged in and placed first, with the `identity`
  field recording ownership.

### 6. request_fill - Request fill

Requests the actual values of a specific credential for filling.

**Request:**

```json
{
  "type": "request_fill",
  "payload": {
    "origin": "https://github.com",
    "item_id": "uuid-v4",
    "user_gesture": true
  }
}
```

**Response:**

```json
{
  "type": "fill_response",
  "ok": true,
  "payload": {
    "username": "user@example.com",
    "password": "hunter2"
  }
}
```

**BankCard fill (since 2026-09):** BankCard credentials can also use `request_fill` (requires
`user_gesture`; a card has no URL, so there is no origin binding check). The `card` field of the
response payload only appears for card fills; the response shape for login fills is unchanged:

```json
{
  "type": "fill_response",
  "ok": true,
  "payload": {
    "username": null,
    "password": null,
    "card": {
      "card_number": "4111 1111 1111 1111",
      "cardholder_name": "ALICE SMITH",
      "expiry_date": "12/29"
    }
  }
}
```

> Security note: **CVV never appears in a `request_fill` response.** A fill targets page
> DOM input fields, which any script on the page can read; CVV is only available through `copy`
> (the clipboard path), and the user clears the clipboard manually after pasting (the bridge
> does not clear it automatically). The extension must likewise never inject CVV into page elements.

**Error codes:**

- `locked` - The vault is locked
- `not_found` - The credential does not exist
- `origin_mismatch` - The request origin does not match the credential URL
- `user_confirmation_required` - User confirmation is required
- `authentication_failed` - Authentication failed

### 7. get_totp - Get TOTP

Returns the current TOTP code for the linked credential.

> Note: TOTP entries must have a URL set for origin binding to apply (otherwise `origin_binding_required` is returned).

**Request:**

```json
{
  "type": "get_totp",
  "payload": {
    "origin": "https://github.com",
    "item_id": "uuid-v4",
    "user_gesture": true
  }
}
```

**Response:**

```json
{
  "type": "totp_response",
  "ok": true,
  "payload": {
    "code": "123456",
    "remaining_seconds": 15,
    "period": 30
  }
}
```

### 8. copy - Copy to clipboard

Asks for a specific field to be copied to the clipboard (performed by the CLI/Desktop).

**Request:**

```json
{
  "type": "copy",
  "payload": {
    "origin": "https://github.com",
    "item_id": "uuid-v4",
    "field": "password",
    "user_gesture": true
  }
}
```

**Response:**

```json
{
  "type": "copy_response",
  "ok": true,
  "payload": {
    "copied": true
  }
}
```

> The clipboard is never cleared automatically: after a copy the user is responsible for clearing it (`clear_after_seconds`
> is never returned).

**`field` values:** `username`, `password`, `totp`, plus the BankCard fields
`card_number` / `cardholder_name` / `expiry_date` / `cvv` (since 2026-09).
Card fields require the credential to be a BankCard and the corresponding field to be non-empty (an empty string returns `not_found`);
a card has no URL, so origin binding always passes for cards.

### 9. passkey_list - List passkeys

Returns passkey summaries for a given RP (relying party) (**no key material of any kind**, non-sensitive fields only).

**Request:**

```json
{
  "type": "passkey_list",
  "payload": {
    "origin": "https://example.com",
    "user_gesture": true,
    "rp_id": "example.com"
  }
}
```

> When `rp_id` is omitted it is derived from the origin's effective domain; if supplied explicitly and it does not match the origin, `passkey_rp_mismatch` is returned.

**Response:**

```json
{
  "type": "passkey_list_response",
  "ok": true,
  "payload": {
    "rp_id": "example.com",
    "items": [
      {
        "id": "uuid-v4",
        "rp_id": "example.com",
        "user_name": "alice@example.com",
        "user_display_name": "Alice",
        "identity_name": "Personal",
        "created_at": 1730000000
      }
    ]
  }
}
```

### 10. passkey_create - Create passkey

Creates a software passkey for the current active identity under the given RP and returns the registration artifact (attestationObject).

**Request:**

```json
{
  "type": "passkey_create",
  "payload": {
    "origin": "https://example.com",
    "user_gesture": true,
    "request_json": {
      "rp": { "id": "example.com", "name": "Example" },
      "user": {
        "id": "b64url-user-handle",
        "name": "alice@example.com",
        "displayName": "Alice"
      },
      "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }]
    },
    "client_data_json_b64": "b64url-clientDataJSON"
  }
}
```

Conventions:

- `request_json` is the JSON form of `PublicKeyCredentialCreationOptions`; every `BufferSource` field (`user.id`, `challenge`, `excludeCredentials[].id`) has already been serialized by the extension into a base64url string
- `pubKeyCredParams` must contain `{type: "public-key", alg: -7}` (ES256), otherwise `passkey_alg_unsupported` is returned
- When `rp.id` is omitted, the origin's effective domain is used; if it does not match the origin, `passkey_rp_mismatch` is returned
- `client_data_json_b64` is the raw clientDataJSON bytes built on the extension side; core only hashes them with SHA-256 into the signature and never reassembles them
- The bridge session has just authenticated with the master password, so persisting `uv_initialized=true` is accurate
- Returns `no_active_identity` when no active identity is set

**Response:**

```json
{
  "type": "passkey_create_response",
  "ok": true,
  "payload": {
    "item_id": "uuid-v4",
    "credential_id_b64": "b64url",
    "attestation_object_b64": "b64url",
    "client_data_json_b64": "b64url（原样回传）",
    "transports": ["internal"]
  }
}
```

### 11. passkey_assert - Passkey assertion

Signs the ceremony with the specified passkey (silent key selection is not allowed: `item_id` is required).

**Request:**

```json
{
  "type": "passkey_assert",
  "payload": {
    "origin": "https://example.com",
    "user_gesture": true,
    "item_id": "uuid-v4",
    "client_data_json_b64": "b64url-clientDataJSON",
    "user_verification": true
  }
}
```

Conventions:

- An omitted `item_id` is rejected outright — the extension's picker UI must require an explicit user selection even when there is only one candidate
- `user_verification` defaults to `true`; the extension maps WebAuthn's `discouraged` to `false`
- A missing passkey returns `passkey_item_not_found`; one belonging to another identity returns `wrong_identity`
- An origin that does not match rp_id returns `passkey_rp_mismatch`

**Response:**

```json
{
  "type": "passkey_assert_response",
  "ok": true,
  "payload": {
    "item_id": "uuid-v4",
    "credential_id_b64": "b64url",
    "authenticator_data_b64": "b64url",
    "signature_der_b64": "b64url",
    "user_handle_b64": "b64url"
  }
}
```

> The signed data is `authenticatorData ‖ SHA-256(clientDataJSON)`; the signature algorithm is ES256 with DER-encoded output.

### 12. passkey_credential_provider_list - Provider-side passkey enumeration

Data-source message for OS passkey providers (Phase 4: macOS AuthenticationServices / Windows Hello plugin):
enumerates the passkeys available for this origin so the system picker UI can display them. The semantics and
validation chain are identical to `passkey_list` (§9) (origin↔rp_id check + user gesture + HMAC);
only the message name and the audit semantics differ.

**Request:**

```json
{
  "type": "passkey_credential_provider_list",
  "origin": "https://example.com",
  "user_gesture": true,
  "payload": { "rp_id": "example.com" }
}
```

**Response:** `passkey_credential_provider_list_response`; the payload has the same shape as §9
(`{items, rp_id}`, non-sensitive summaries, no key material).

### 13. passkey_credential_provider_assert - Provider-mediated assertion

The OS provider performs the assertion on the user's behalf after the selection has been completed in the system UI.
The trust chain is identical to `passkey_assert` (§11): user gesture + the desktop approval gate (the op name is passed through as
`passkey_credential_provider_assert`, so the popup UI can identify the source) + the core-side
origin↔rp_id check + the sensitive-operation gate. The only difference is auditing: the `passkey_asserted` event carries
`via=os_provider` metadata (the extension path is `via=extension`), so provider assertions are independently traceable.

**Request / Response:** same shape as §11; the response type is
`passkey_credential_provider_assert_response`.

> A v2 extension receives `unknown_type` for these two new messages (backwards compatible).

### 14. find_for_save - Pre-save duplicate check (protocol v4)

Called by the extension's save/update bar after form submission: looks up existing
same-site, same-username password entries by host + username, so the bar can default to
"update" or "save as new". Pure metadata (no ciphertext or password
material), on the same level as `get_suggestions` — session authentication only, no user gesture required.

**Request:**

```json
{
  "type": "find_for_save",
  "payload": {
    "origin": "https://example.com",
    "username": "bob@example.com"
  }
}
```

**Response:** `find_for_save_response`

```json
{
  "matches": [
    { "item_id": "…", "name": "Example Login", "username": "bob@example.com" }
  ]
}
```

Matching rule: password type + `validate_origin_binding` + username equality after trimming,
case-insensitive. `validate_origin_binding` lets URL-less entries through outright
(no site attribution is checked, only username equality decides), so **URL-less entries take part in matching as well**
(known behavior: when an entry cannot be attributed to a site, username alone decides).

### 15. save_credential - Save / update login (protocol v4)

The write path behind a single explicit click on the save bar. An omitted `item_id` means create (bound to the request origin,
`SecurityLevel::High`, name from `name_hint` falling back to the host, and the email inside the username
is copied into the payload's email field); a present `item_id` means update that entry's password — **only the
password field is replaced**, the rest of the payload (email, security questions) is kept as-is; an update must carry an explicit
item_id — there is no "pick one to overwrite on the user's behalf" path.

**Gates** (isomorphic to the passkey write path): user gesture required (the save-bar click) → the desktop approval
gate (op=`credential_save`, auto/require/off semantics as in the previous section) → active identity check
(mandatory for create; for update the entry must belong to the active identity) → origin binding check (on update, a TLD+1 match is enforced whenever the entry has
a URL) → audit `bridge_save_credential`.

**Request:**

```json
{
  "type": "save_credential",
  "payload": {
    "origin": "https://example.com",
    "user_gesture": true,
    "item_id": "…（更新时；缺省 = 新建）",
    "username": "bob@example.com",
    "password": "…",
    "name_hint": "Example — Sign In"
  }
}
```

**Response:** `save_credential_response`

```json
{ "item_id": "…", "action": "created", "name": "Example Login" }
```

Error codes: `user_gesture_required`, `invalid_payload` (empty password),
`save_desktop_denied`, `no_active_identity`, `not_found`,
`unsupported_credential_type`, `wrong_identity`, `origin_mismatch`,
`locked` / `authentication_failed`.

Extension-side behavior (reference implementation in `browser/chromium-extension/src/content.ts`): after form submission
(a real `submit` event or an SPA submit-button click) the fields are captured → the save bar offers four choices, "Save / Update /
Never for this site / Dismiss"; only that single explicit click counts as `user_gesture`. Most logins navigate away,
so the captured proposal is parked in `chrome.storage.session` (in-memory, never written to disk); the landing page retrieves it within 2 minutes
by **exactly identical** origin and replays the save bar; dismissing drops the parked proposal, and "Never for this site" is recorded per
origin in storage. Blocked / suspicious domains pass the same gate as fills — writing a password into a phishing
site is just as harmful as filling one in.

### 16. generate_password - Password generation (protocol v5)

A pure computation message: it neither reads nor writes the vault, needs only session authentication, and requires no user gesture.

**Request:**

```json
{
  "type": "generate_password",
  "payload": {
    "length": 16,
    "include_lowercase": true,
    "include_uppercase": true,
    "include_digits": true,
    "include_symbols": true,
    "pronounceable": false,
    "words": null
  }
}
```

- Every field may be omitted: `length` defaults to 16, all four character sets default to on, `pronounceable` defaults to false
- `words` (Diceware word count, 3–10), when given, overrides `length` and the character set settings
- Validation failures (`length` out of range, `words` out of range, or no character set enabled outside words mode) return `invalid_payload`

**Response:** `generate_password_response`

```json
{ "password": "…" }
```

A generation failure returns `generation_failed`.

### 17. sync_connect - Cloud sync bootstrap (protocol v6)

Hands the local sync configuration to the extension: the bridge issues the `(server_url, token, device_id, group_key)` quartet,
and the extension then connects **directly over HTTP** to the sync server's `/api/v1/sync/*` to fetch and decrypt the cloud vault — the data plane
bypasses the native messaging bridge, which only handles authentication and key handover (M5 batch 1).

The zero-knowledge invariant is unaffected: the token and group key only enter the extension's `chrome.storage.session`
(in-memory; lost when the browser closes); the bridge reads the OS keyring (`persona-sync` / `persona-device`,
the same entries the desktop uses) and the server URL from the workspace settings, never decrypting any entry.

**Request:**

```json
{
  "type": "sync_connect",
  "payload": {
    "user_gesture": true
  }
}
```

- Triple gate: paired-session HMAC + `user_gesture: true` (omitted → `user_gesture_required`;
  this message hands out the vault decryption key, so it must be triggered by an explicit click) + a session is mandatory (unpaired → `pairing_required`)
- Gate order: session authentication first, then payload parsing, then the gesture check

**Response:** `sync_connect_response`

```json
{
  "server_url": "https://sync.example.com",
  "token": "…",
  "device_id": "…",
  "device_name": "…",
  "group_key_hex": "…64 hex chars…"
}
```

- `group_key_hex`: the sync group's group key (64 hex characters, same encoding as the desktop sync_group_store)
- The token comes from the OS keyring; the device identity comes from the `persona-device` entry

**Error codes (new in v6):**

| Error code                | Trigger                                                                                       |
| ------------------------- | --------------------------------------------------------------------------------------------- |
| `sync_not_configured`     | No sync token in the keyring / no workspace / empty server URL / invalid configuration        |
| `sync_not_joined`         | No device identity in the keyring (this vault has not joined sync)                            |
| `sync_not_authorized`     | No envelope for this device in the envelope table (awaiting admin authorization, fail-closed) |
| `sync_group_key_failed`   | Unwrapping this device's group key envelope failed                                            |
| `sync_identity_corrupted` | The stored device identity is unreadable                                                      |
| `sync_server_unreachable` | The remote `group_keys()` call failed                                                         |

### 18. account_login / account_status / account_logout - Account-domain trio (protocol v7)

The extension logs in / queries / logs out of the **account-domain** session through the local bridge (M5 batch 2): all SRP math (Argon2id pre-hash, M1 derivation, M2 verification)
runs on the host Rust side (orchestrated by core `AccountsApi::srp_login`), and the password and premaster secret never leave the orchestration module.
The token is written straight to the OS keyring (`persona-account` entry, key = vault db_path, same name and key as the desktop token_store) — **the token itself never crosses the bridge protocol**;
the extension only sees the expiry and the session fingerprint. The server URL reuses the sync configuration from the vault settings
(the same read path as §17).

**account_login request:**

```json
{
  "type": "account_login",
  "payload": {
    "account_id": "acct-…",
    "password": "…",
    "device_name": "browser-extension",
    "user_gesture": true
  }
}
```

- Gates: paired-session HMAC + `user_gesture` (a password is exchanged for a token — a sensitive operation)
- Response `account_login_response`: `{ "expires_in_secs": 900, "session_key_fingerprint": "…hex…" }`
- Failure classification: `sync_not_configured` (server URL not configured), `account_not_configured`
  (invalid URL), `account_login_failed` (SRP orchestration failure, including server rejection),
  `account_keyring_unavailable` (writing the token to the keyring failed — a successful login is still not delivered,
  fail-closed)

**account_status request:** `{}` (requires a paired session, no gesture requirement — it only reports presence)

- Response `account_status_response`: `{ "has_session": true, "server_configured": true }`

**account_logout request:**

```json
{
  "type": "account_logout",
  "payload": { "account_id": "acct-…", "user_gesture": true }
}
```

- Gates: paired-session HMAC + `user_gesture`
- Same semantics as the desktop `account_sign_out`: no token = idempotent success
  (`revoked_on_server: false`); with a token, best-effort revocation of the server session
  (`DELETE /accounts/{id}/sessions/{token}`) — **the local token is deleted regardless of whether the
  server is reachable**, and `revoked_on_server` reports the revocation outcome faithfully
- Response `account_logout_response`: `{ "revoked_on_server": false }`

### 19. sync_push_now - Sync now (protocol v7)

The cloud write path (M5 batch 3): the host opens a `SyncSession` and runs the backfill → pull →
materialize → push cycle, pushing the main database (including extension-side writes persisted via `save_credential`)
to the cloud. Same core orchestration as the desktop `sync_now`; the differences:

- The master key comes from the bridge's lock state (`PERSONA_MASTER_PASSWORD`); locked → `locked:`
- **No capture seam is attached** — the bridge is one process per request, and the seam dies with the process; writes persisted through the bridge outside of a request
  are picked up idempotently by the next `backfill_existing` round

**Request:**

```json
{
  "type": "sync_push_now",
  "payload": { "user_gesture": true }
}
```

- Gates: paired-session HMAC + `user_gesture` (a write path pushing to the cloud)
- Response `sync_push_now_response` (a count summary with the same fields as core `SyncNowReport`):

```json
{
  "pulled": 0,
  "materialized": 0,
  "conflicts": 0,
  "pending_identity": 0,
  "pushed": 3,
  "backfilled": 0
}
```

- Failure classification: `sync_not_configured` / `sync_not_joined` /
  `sync_identity_corrupted` (configuration stage, before unlock), `sync_session_failed`
  (envelope unwrap/assembly failure), `sync_cycle_failed` (backfill or cycle failure),
  `locked:` (the bridge's lock state has no master password)

### 20. sync_resolve_conflict - Conflict resolution (protocol v7)

The resolution entry point for true conflicts (same entry, equal lamport, concurrent double versions with different device_id)
(M5 batch 4): adopts the concurrent copy pointed to by `adopt_op_id`, whose content overwrites the current
winner in the vault, and the remaining copies are dropped from the view. Same core orchestration as the desktop `SyncConflictsModal`
(`SyncSession::resolve_conflict`, main database first, then the oplog).

**Request:**

```json
{
  "type": "sync_resolve_conflict",
  "payload": {
    "item_id": "018f3c2a-…",
    "adopt_op_id": "018f3c2b-…",
    "user_gesture": true
  }
}
```

- Gates: paired-session HMAC + `user_gesture` (resolution overwrites the losing copy — it must not happen silently)
- Validation order: `item_id` / `adopt_op_id` must be valid UUIDs (`invalid_payload:`),
  before any configuration/unlock check
- Response `sync_resolve_conflict_response`: `{ "resolved": true }`
- Failure classification: `sync_not_configured` / `sync_not_joined` /
  `sync_identity_corrupted` (configuration stage, before unlock), `sync_session_failed`
  (assembly failure), `sync_resolve_failed` (the adopted copy does not exist — most likely already
  resolved elsewhere, or not a Credential kind), `locked:`

## Security Mechanisms

### Origin binding

Every request that touches sensitive data must include the `origin` field:

1. The extension obtains the current page origin from `window.location.origin`
2. The CLI verifies that the origin matches the credential URL (or the passkey's rp_id)
3. On a mismatch it returns `origin_mismatch` (credential classes) or `passkey_rp_mismatch` (passkey classes)

### User gesture requirement

`request_fill` / `get_totp` / `copy` / `passkey_*` / `save_credential` / `sync_connect` / `account_login` / `account_logout` / `sync_push_now` / `sync_resolve_conflict` operations require:

1. Triggering by an explicit user action (a click or a keyboard shortcut)
2. `user_gesture: true` in the request to indicate a deliberate user action (for passkeys, the extension reads `navigator.userActivation.isActive` synchronously at the MAIN-world interception point)
3. The CLI can be configured to require a desktop-notification confirmation for unconfirmed requests (see the next section)

### Desktop approval (passkey confirmation gate)

`passkey_create` / `passkey_assert` / `passkey_credential_provider_assert`
(§13) / `credential_save` (§15) can require a second confirmation while the desktop app is running — independent of the
extension's self-reported user gesture, so a compromised extension cannot sign or write silently (threat model in `PASSKEYS_DESIGN.md` §10).

**Transport**: the bridge (a short-lived process per request) connects as a client to the Unix domain socket
`<agent state dir>/passkey-approval.sock` (default `~/.persona/passkey-approval.sock`,
overridable via `PERSONA_PASSKEY_APPROVAL_SOCKET`; mode 0600). One connection per request, JSON line protocol:

Request (bridge → desktop):

```json
{
  "v": 1,
  "op": "passkey_assert",
  "rp_id": "github.com",
  "origin": "https://github.com",
  "user_name": "alice",
  "item_id": "<uuid>"
}
```

- `op` whitelist: `passkey_create` / `passkey_assert` /
  `passkey_credential_provider_assert` / `credential_save`; `passkey_list`
  is non-sensitive and bypasses approval (it is outside the whitelist, and receiving it is rejected as `unsupported`)

Response (desktop → bridge):

```json
{"approved":true}
{"approved":false,"reason":"denied"}
```

- `reason` values: `denied` (rejected by the user or frontend), `timeout` (no reply from the desktop within 120s; the bridge
  disconnects after a 150s backstop), `locked` (the desktop is locked; rejected outright without a popup), `unsupported` (malformed JSON /
  unknown version / unknown op)

**Switch** `PERSONA_BRIDGE_DESKTOP_APPROVAL` (default `auto`):

| Value     | Behavior                                                                                                                                         |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `auto`    | Socket present → desktop approval is mandatory; desktop not running / connection failed → existing behavior (the gesture gate applies as before) |
| `require` | Policy-enforced: reject the passkey request even when the socket is absent (fail closed)                                                         |
| `off`     | Never ask                                                                                                                                        |

On denial or unreachability the bridge returns an error for that request, with an error-code prefix that varies by op:
`passkey_desktop_denied: <op> rejected by desktop approval (<reason>)`,
`save_desktop_denied: ...` (save path),
`passkey_desktop_approval_required: ...` (desktop unreachable in `require` mode).

This protocol is a local implementation detail and does not consume a bridge protocol version number (`protocol_version` is carried by the hello
response, currently 5; see `CLIENT_COMMUNICATION_ARCHITECTURE.md` for the direction of the next version).

### Session management (optional)

When `pairing_required: true` (on by default; disable with `PERSONA_BRIDGE_REQUIRE_PAIRING=0`):

1. On first connection the extension must complete the pairing flow (`pairing_request` → user approval → `pairing_finalize`)
2. A pairing key is generated after successful pairing (stored locally by the extension), and a short-lived session is issued (24 hours by default)
3. For sensitive operations (suggestions / fill / TOTP / copy), the extension must carry the `auth` (HMAC) field
4. The local bridge persists pairing state to `~/.persona/bridge/state.json` (overridable via `--state-dir`)

#### HMAC signing input

For every request that requires authentication, compute:

```
<type>\n<request_id>\n<payload_json>\n<session_id>\n<ts_ms>\n<nonce>
```

- `payload_json` is serialized as key-sorted JSON (canonical JSON)
- `signature = base64url_no_pad(HMAC_SHA256(pairing_key, signing_input))`

### Sensitive operation confirmation

The following policy keys are **planned and not yet implemented** (the bridge/CLI does no configuration reading for them and does not
change behavior accordingly):

- `confirm_on_unknown_origin` - First request for an unknown domain (not implemented)
- `confirm_on_fill` - Confirmation required for every fill (not implemented)
- `require_biometric` - Biometric authentication required for sensitive operations (not implemented)

The confirmation mechanisms actually in effect today are the user gesture gate plus the desktop approval gate (see above).

## Audit Log

Sensitive operations in a bridge session are recorded as structured log events (Tracing, written to the bridge process log).
The event names are:

- `bridge_fill_success` - A credential fill succeeded
- `bridge_totp_success` - TOTP generated
- `bridge_copy_success` - Clipboard copy
- `bridge_save_credential` - Save/update login
- `bridge_passkey_create` / `bridge_passkey_assert` - Passkey write/assertion
- `bridge_generate_password` - Password generated
- `bridge_passkey_list` - Passkey enumeration (**debug level**; not emitted at the default info level)

This is not "every operation is logged by default": `passkey_list` is only visible at debug level, and these are
log events, not rows in the database `audit_log` table.

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "event": "bridge_fill_success",
  "origin": "https://github.com",
  "item_id": "uuid-v4",
  "result": "success",
  "extension_id": "chrome-extension://xxx"
}
```

## Error Handling

### Generic error response

```json
{
  "type": "error",
  "ok": false,
  "error": "error_code: Human readable message",
  "payload": null
}
```

### Error code list

| Error code                          | Description                                                            |
| ----------------------------------- | ---------------------------------------------------------------------- |
| `invalid_json`                      | JSON parsing failed                                                    |
| `unknown_type`                      | Unknown message type                                                   |
| `locked`                            | The vault is locked and needs unlocking                                |
| `not_found`                         | The requested resource does not exist                                  |
| `origin_mismatch`                   | Origin does not match                                                  |
| `origin_binding_required`           | The entry has no URL set, so origin binding cannot apply               |
| `authentication_failed`             | Authentication failed                                                  |
| `wrong_identity`                    | The current active identity does not match                             |
| `user_confirmation_required`        | User confirmation is required                                          |
| `session_expired`                   | The session has expired                                                |
| `user_gesture_required`             | Missing user gesture (v2)                                              |
| `no_active_identity`                | No active identity is set (v2)                                         |
| `passkey_rp_mismatch`               | Origin does not match the passkey's rp_id (v2)                         |
| `passkey_alg_unsupported`           | pubKeyCredParams does not include ES256 (v2)                           |
| `passkey_item_not_found`            | The specified passkey does not exist (v2)                              |
| `passkey_origin_mismatch`           | Passkey origin check failed (reserved) (v2)                            |
| `passkey_desktop_denied`            | Passkey create/assertion denied by desktop approval                    |
| `passkey_desktop_approval_required` | Desktop approval unreachable in `require` mode                         |
| `save_desktop_denied`               | Save/update denied by desktop approval (v4)                            |
| `unsupported_credential_type`       | The entry type does not support this operation                         |
| `invalid_payload`                   | Payload validation failed (e.g. empty password)                        |
| `invalid_request`                   | Parameter validation failed (bridge.rs:1297/1300)                      |
| `passkey_assert_failed`             | Passkey assertion orchestration failed (bridge.rs:1336)                |
| `sync_not_configured`               | Sync not configured (token/URL/workspace missing) (v6)                 |
| `sync_not_joined`                   | The vault has not joined sync (v6)                                     |
| `sync_not_authorized`               | The device has no group key envelope yet (awaiting authorization) (v6) |
| `sync_group_key_failed`             | Group key envelope unwrap failed (v6)                                  |
| `sync_identity_corrupted`           | The device identity is unreadable (v6)                                 |
| `sync_server_unreachable`           | The sync server is unreachable (v6)                                    |
| `account_not_configured`            | Invalid account server URL (v7)                                        |
| `account_login_failed`              | SRP login orchestration failed (including server rejection) (v7)       |
| `account_keyring_unavailable`       | Account token keyring read/write failed (v7)                           |
| `sync_session_failed`               | Sync session assembly failed (envelope/authorization) (v7)             |
| `sync_cycle_failed`                 | Sync cycle failed (backfill/cycle) (v7)                                |
| `sync_resolve_failed`               | Conflict resolution failed (copy missing / not a Credential) (v7)      |

## Configuration

### Environment variables

| Variable                          | Description                                      | Default                    |
| --------------------------------- | ------------------------------------------------ | -------------------------- |
| `PERSONA_MASTER_PASSWORD`         | Master password (automation scenarios)           | -                          |
| `PERSONA_DB_PATH`                 | Database path                                    | `~/.persona/identities.db` |
| `PERSONA_BRIDGE_STATE_DIR`        | Bridge state directory (pairing/session)         | `~/.persona/bridge`        |
| `PERSONA_BRIDGE_REQUIRE_PAIRING`  | Whether to enforce pairing + HMAC                | `true`                     |
| `PERSONA_BRIDGE_REQUIRE_GESTURE`  | Whether to enforce user_gesture (fill/totp/copy) | `true`                     |
| `PERSONA_BRIDGE_AUTH_MAX_SKEW_MS` | Maximum HMAC timestamp skew (replay protection)  | `300000`                   |

### CLI parameters

```bash
persona bridge [OPTIONS]

OPTIONS:
    --db-path <PATH>    指定数据库路径
    --approve-code <C>  批准配对码（执行后退出）
    --state-dir <PATH>  配对状态目录（默认 ~/.persona/bridge）
```

## Native Host Manifest

### macOS

Location (by browser):

- Chrome: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.persona.native.json`
- Chromium: `~/Library/Application Support/Chromium/NativeMessagingHosts/com.persona.native.json`
- Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.persona.native.json`
- Edge: `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/com.persona.native.json`

```json
{
  "name": "com.persona.native",
  "description": "Persona Password Manager Bridge",
  "path": "~/.persona/bin/persona-bridge",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://YOUR_EXTENSION_ID/"]
}
```

### Linux

Location (by browser):

- Chrome: `~/.config/google-chrome/NativeMessagingHosts/com.persona.native.json`
- Chromium: `~/.config/chromium/NativeMessagingHosts/com.persona.native.json`
- Brave: `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.persona.native.json`
- Edge: `~/.config/microsoft-edge/NativeMessagingHosts/com.persona.native.json`

The manifest structure is the same as above.

### Windows

Registry key (the default value is the manifest file path):

`HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts\com.persona.native`

Example default value:

`C:\Users\<YOU>\AppData\Local\Persona\native-messaging\com.persona.native.json`

Example manifest file contents:

```json
{
  "name": "com.persona.native",
  "description": "Persona Password Manager Bridge",
  "path": "C:\\Program Files\\Persona\\persona.exe",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://YOUR_EXTENSION_ID/"]
}
```

## Protocol Version Compatibility

| Protocol Version | CLI Version | Features                                                                                                                                                                                                                       |
| ---------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1                | 0.1.0+      | hello/status/pairing_request/pairing_finalize + HMAC auth + get_suggestions/request_fill/get_totp/copy                                                                                                                         |
| 2                | 0.1.0+      | everything in v1 + passkey_list/passkey_create/passkey_assert (software passkey track)                                                                                                                                         |
| 3                | 0.1.0+      | everything in v2 + passkey_credential_provider_list/assert (OS provider data source / delegated assertion, P4.1/P4.4)                                                                                                          |
| 4                | 0.1.0+      | everything in v3 + find_for_save/save_credential (vault write path: save or update a login, §14/§15)                                                                                                                           |
| 5                | 0.1.0+      | everything in v4 + generate_password (password generation, §16) + the hello response carries connect_available/connect_port                                                                                                    |
| 6                | 0.1.0+      | everything in v5 + sync_connect (cloud sync bootstrap, §17): the extension fetches the connection parameters through the bridge and then talks to the data plane over HTTP directly                                            |
| 7                | 0.1.0+      | everything in v6 + account_login/status/logout (the account-domain trio, §18) + sync_push_now (sync now, §19) + sync_resolve_conflict (conflict adjudication, §20): tokens land only in the keyring and never cross the bridge |

> From v2 onward the frame format and the HMAC signing rules are unchanged; only new message types were added and `protocol_version` was bumped. Older extensions still get `unknown_type` for messages the bridge does not know, so compatibility is preserved.

## Installation Scripts

- macOS / Linux: `scripts/native-messaging/install-native-host.sh <EXTENSION_ID>`
- Windows: `scripts/native-messaging/install-native-host.ps1 -ExtensionId <EXTENSION_ID>`

### Safari Transport Mapping (Same Protocol, Host Side Pending Real-Device Verification)

Safari Web Extensions have no NMH stdio channel: `browser.runtime.sendNativeMessage(<app
bundle id>, …)` hands the same JSON payload to the host app's `SafariWebExtensionHandler`,
and the host process spawns `persona bridge` on the extension's behalf (one request / one
process semantics unchanged, zero changes to the bridge protocol layer). The extension side
already has a transport shim that prefers `browser` and falls back to `chrome`, and
`setNativeHost(bundleId)` injects the host bundle id; the Swift host side (payload →
`persona bridge` subprocess wrapper) depends on macOS/Xcode and is parked pending a
real-device batch (see `browser/safari-extension/README.md`).

## References

- [Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
- [1Password Browser Extension Architecture](https://support.1password.com/getting-started-browser/)
