# FAQ

## Can I recover a lost master password?

**No.** There is no escrow, no reset back door — the master password derives the
encryption key, and a lost key means the vault stays closed forever. That is the
price of end-to-end encryption: the master password is derived only on your
machine, no party can bypass it, and that is exactly why it does not need to
trust anyone. Make
[backups](/en/user/quick-start#backups-do-this-right-now) a habit.

## Where is my data stored?

By default `~/.persona/` (overridable via `--path` or
`PERSONA_WORKSPACE_PATH`): the `identities.db` main vault (SQLite),
`attachments/` for attachment ciphertext, `backups/` and other working
directories. Note: **credential payloads are ciphertext, but metadata columns
(name, URL, username) are plaintext SQLite** — for scenarios where even metadata
must stay secret, use Travel Mode or full-disk encryption.

## Do I need a server, or a network connection?

**No.** Purely local, zero network by default, with every feature usable. Sync,
audit copies, and backup escrow are all optional add-ons; self-host a Persona
Server when you need them.

## Can the server see my passwords?

**No.** The sync relay only ever sees ciphertext oplog entries, device
envelopes, and timestamps; credential content (URL, username, password, TOTP) is
all encrypted and decrypted on the client. A server operator can only DoS
(refuse to forward) — theft is impossible. For the detailed boundaries, see
[THREAT_MODEL](https://github.com/cuihairu/persona/blob/main/docs/THREAT_MODEL.md).

## Which platforms are supported?

| Platform          | Status                                                      |
| ----------------- | ----------------------------------------------------------- |
| Linux desktop app | Primary delivery (deb, reproducible build)                  |
| CLI / SSH Agent   | Supported (cargo build, cross-platform)                     |
| Browser extension | Chromium family                                             |
| macOS / Windows   | Not verified on real hardware; support not claimed          |
| Mobile            | Native projects in repo (iOS/Android/HarmonyOS, unreleased) |

## Do attachments sync?

**No.** Attachment ciphertext is written to local disk (encrypted reusing the
owning credential's item key) and does not participate in sync; v1 backup
exports also exclude attachments.

## How is this different from 1Password / Bitwarden?

Persona is **local-first + self-hosted**: no vendor cloud, no account system,
and the server (if any) is a relay you run yourself. For positioning
differences, see [Project Introduction](/en/overview/introduction).

## Does it lock automatically?

Yes. Locking drops the key (the master key does not stay in memory); sensitive
operations like viewing ciphertext or changing the master password also require
**re-authentication**. The desktop app can enable biometric unlock (on Linux via
the OS keychain / Secret Service, with the master password kept in the system
keyring).

## Is it open source?

Yes, MIT license. For build instructions, see
[Environment Setup](/en/development/setup).
