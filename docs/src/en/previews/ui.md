# UI Previews

Design prototypes and UI screenshots of the desktop app, in both light and dark
themes. These assets share the same source files as the UI Preview section of
the repository README and the [desktop app](/en/user/desktop) page
(`docs/branding/ui/`, with site copies under `docs/src/public/ui/`).

## Main View (Light and Dark Themes)

![Light theme full window](/ui/light-full.png)

**Light theme, full window**: three-pane layout — left sidebar (identity
switcher, search, group navigation, vault / tags / tools), center credential
list (favorites, security-level badges, one-click copy), right detail panel
(URL, username, tags, attachments, item history; sensitive fields masked by
default).

![Dark theme full window](/ui/dark-full.png)

**Dark theme, full window**: the same layout in dark form. Semantic color tokens
flip as a whole with the theme — it is not a simple inversion.

## Sidebar Close-ups

![Light sidebar close-up](/ui/light-sidebar.png)

**Light sidebar close-up**: 1Password-style group navigation — All Items /
Favorites / Recently Used, categories shown in Chinese (passwords, passkeys,
secure notes, API keys, SSH keys, software licenses, ID documents, crypto
wallets, game tokens), vaults, tags and a tools area (statistics, SSH Agent,
wallet, security watchtower, generator), with settings and session lock at the
bottom.

![Dark sidebar close-up](/ui/dark-sidebar.png)

**Dark sidebar close-up**: the same structure in dark form.

## Before and After the Redesign

![Sidebar before redesign](/ui/sidebar-before-redesign.png)

**Sidebar before the redesign**: flat panel menu, categories shown under their
raw English enum names, no search or Recently Used group — a before/after
contrast to the close-ups above.

## Mobile (Android)

![Android mobile home screen](/ui/mobile-android-home.png)

**Android home screen (empty vault state)**: a real build of the native Kotlin +
JNI bridge (`mobile/rust`) running in an emulator — master password entry with
initialize / unlock buttons.

The three screenshots below show the three tabs of the main area after
unlocking (in-device walkthrough on 2026-10-11, seeded vault with 4
credentials):

![Android data tab](/ui/mobile-android-data.png)

**Data tab**: the credential list fetched through the business FFI
(`persona_credential_search`), showing metadata only (name + username / type);
payloads are not decrypted.

![Android tools tab](/ui/mobile-android-tools.png)

**Tools tab**: reload the credential list, lock the session.

![Android settings tab](/ui/mobile-android-settings.png)

**Settings tab**: bridge status, bridge version, vault path, credential count.

## CLI Terminal Sessions

Real terminal output from the `persona` CLI (recorded 2026-10-12, demo
workspace and demo data).

![persona command overview](/ui/cli-help.png)

**Command overview**: `persona --help` — workspace initialization,
identity/credential management, SSH, TOTP, wallet, passkeys, password
generation, backup, travel mode, Connect automation, secrets injection, and
other subcommands visible in a single screen.

![Credential list](/ui/cli-credentials.png)

**Credential list**: `persona credential list` — credential metadata listed by
owning identity (name, type, username, favorite flag); plaintext never leaves
the vault, and reading it requires an explicit `show` plus an unlocked session.

![Password generation](/ui/cli-password-generate.png)

**Password generation**: `persona password generate` — two output modes, random
and passphrase (Diceware passphrase, EFF large word list).

## Browser Extension (Chromium)

![Chromium extension popup](/ui/extension-chromium-popup.png)

**Persona Autofill extension popup**: its real state once connected to the
local `persona` process through the Native Messaging bridge (top bar shows
"Connected • Unlocked"). The popup offers pairing, fill policies, cloud vault
push/pull, and account login entry points; in-page autofill suggestion popover
assets will be added later.

## Prototype Gap List

The following key views do not yet have matching prototypes / screenshot assets
(pending; they will be added to this page once assets land):

| View                                        | Description                                                                                                                                                                                       |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SSH Agent panel                             | Managed key list, agent start/stop, signing approval dialog                                                                                                                                       |
| Settings · Security Center                  | Change master password, biometric unlock, auto-lock, travel mode                                                                                                                                  |
| Settings · Sync Devices                     | Device enrollment / authorization / revocation, conflict resolution queue                                                                                                                         |
| Item Detail · Reveal Secret                 | Re-authentication flow for revealing sensitive fields (masked → plaintext)                                                                                                                        |
| New / Edit Credential Dialog                | Categorized fields, password generator, form validation                                                                                                                                           |
| Statistics / Security Watch                 | In-vault metadata reports, weak / reused password detection                                                                                                                                       |
| Quick Access                                | Quick-lookup panel summoned by a global hotkey                                                                                                                                                    |
| Browser Extension · Fill Suggestion Popover | In-page fill suggestion popover and identity switching (popup main view already included, see above)                                                                                              |
| Mobile (Android / iOS / HarmonyOS)          | Android empty-vault home screen and the data / tools / settings tabs are already included (above); iOS and HarmonyOS native UIs are still missing (no matching build environment on this machine) |

See [Asset Inventory](/en/previews/assets) for where the assets come from,
their change history, and delivery conventions.
