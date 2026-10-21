# Desktop App

The desktop app (Tauri + React) is Persona's main delivery surface: credential
management, identity switching, sync adjudication, SSH approval — it all happens
here. This page is a tour of the feature areas; for installation and first run,
see Quick Start.

## UI Preview

The desktop form after the 1Password-style sidebar redesign (same asset batch
as the UI Preview section of the repo README; source files in
`docs/branding/ui/`).



Light theme full window: a three-column layout with the sidebar (identity
switcher + search + group navigation) on the left, the credential list in the
middle, and the detail panel on the right.



Dark theme full window: the same layout in dark form; semantic color tokens flip
automatically with the theme.



Light theme sidebar close-up: All Items / Favorites / Recently Used, category
groups with Chinese localization, the vault, tags and tools areas, with settings
and session lock at the bottom.



Dark theme sidebar close-up: the same structure in dark form.



The form before the sidebar redesign (forming a before/after comparison with
the close-ups above): flat panel menu, type labels showing the raw English
enum names, no search or recently-used grouping.

## Main Window

- **Sidebar and identity switcher**: credential views isolated by identity
  (work / personal / dev…), one-click switching of the active persona — every
  list, suggestion, and fill default follows the current identity.
- **Credential list and details**: name / URL / username / TOTP / attachments;
  sensitive fields are masked by default, and clicking to reveal requires
  **re-authentication** (shoulder-surfing protection + prevention of silent
  background reads).
- **Quick search**: instant filtering across the current identity's credentials.
- **New credential**: supports password, API key, TOTP, SSH key, attachment
  upload.

## Security Center (in Settings)

- **Change master password**: re-wraps the whole vault; rejected while travel
  mode is active (leave travel mode first).
- **Biometric unlock**: once enabled, the master password is kept in the OS
  keychain and you can unlock with platform biometrics after lockout (on Linux
  via Secret Service).
- **Auto-lock**: locking drops the key — the master key does not stay in
  memory, and unlocking requires re-authentication.
- **Travel mode**: for long offline stretches, actively strip local key
  material, restore on passphrase.

## Sync Devices (in Settings)

- **Join / authorize**: a new device registers here and waits for an authorized
  device to let it in; **an envelope icon = authorized**; unauthorized devices
  receive no data at all.
- **Revoke**: a lost device is kicked out immediately (envelope and session
  state cleared in cascade).
- **Rotate group key**: one click re-seals for the whole group; if another device
  just finished rotating you get a targeted hint — retry, and your data is
  unaffected.
- **Conflict adjudication**: when the same credential is edited concurrently
  offline, both versions enter the adjudication queue and you choose which to
  keep (Lamport clocks determine primary position; nothing is silently
  overwritten).

## Quick Access and Appearance (in Settings)

- **Quick Access search overlay**: a borderless always-on-top panel summoned by
  an OS-level global hotkey; searches credentials across the current identity
  instantly and copies; pressing the hotkey again collapses it and returns focus
  to the original app. Enable it and bind an accelerator on the settings page
  (off by default — global hotkeys are an explicit opt-in).
- **Generator overlay**: a second, independent hotkey summons the password
  generator panel directly, with no effect on the search overlay (rebinding one
  only unregisters its own old key).
- **Squatting status reported honestly**: if the hotkey is already taken by
  another app/window manager, or the platform does not support it, the
  registration failure reason is shown directly on the settings page instead of
  being silently swallowed; bindings persist in workspace settings and are
  re-delivered automatically after a successful unlock.
- **Theme**: follow system / light / dark.

Boundaries (recorded honestly):

- On Linux, global hotkeys only work on X11; Wayland sessions need XWayland,
  otherwise registration fails with the reason reported honestly, without
  affecting main app startup.
- Summoning the overlay while the vault is locked only shows a "unlock first"
  notice and brings the main window to the foreground — the overlay does not
  replicate the unlock flow (registered in THREAT_MODEL).

## SSH Agent and Automation

- **SSH Agent panel**: view hosted keys and signing policies; signature requests
  raise an **approval dialog** (known_hosts verification, confirmation, active
  refusal with an audit trail when rate limits are hit).
- **Connect automation** (in Settings): a local HTTP API for scripts to read
  credentials, passphrase-protected + shown in cleartext exactly once, see
  [CONNECT_AUTOMATION_DESIGN.md](https://github.com/cuihairu/persona/blob/main/docs/CONNECT_AUTOMATION_DESIGN.md).

## Other Panels

- **Health scan (Watchtower)**: a local metadata report on weak / reused /
  expired credentials; optional breach check (HIBP k-anonymity, only a
  5-character hash prefix leaves the machine).
- **Passkeys**: local passkey provider panel and request approval.
- **Wallets**: crypto-asset panel (shipped, M5 graduation track; key hierarchy
  and decisions in [WALLET_DESIGN](https://github.com/cuihairu/persona/blob/main/docs/WALLET_DESIGN.md)).

For unified security semantics and threat boundaries, see
Security Features and
[THREAT_MODEL](https://github.com/cuihairu/persona/blob/main/docs/THREAT_MODEL.md).
