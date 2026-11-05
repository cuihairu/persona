# Desktop Fill Injection (Windows)

One-liner: after the user picks a credential in the Quick Access floating window,
Persona shows the target app's name and asks for explicit confirmation, then injects
username/password into the app that held the foreground **before** the floating
window appeared — the desktop-app sibling of the browser extension's fill
(FEATURE_GAP_ANALYSIS #12). Security posture revised 2026-11-06 after the
codex-2026-11-05 review (see `docs/评审/codex-2026-11-05-desktop-fill-vuln.md`).

## Scope (honest boundaries)

- **Fill belongs to the target side**: browser fill stays with the browser
  extension (Native Messaging bridge, #22); this path is for native desktop apps.
  Self-drawn UI toolkits (Electron, Qt, browsers) are not covered — see
  "Injection strategy".
- **Windows only** for now. On Linux/macOS the commands report "not implemented"
  instead of pretending (`fill_supported()`).
- **Password-type credentials only** (username + password fields).

## Injection strategy (selection)

| Option                               | Verdict               | Why                                                                                                                                                                                                                               |
| ------------------------------------ | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **WM_SETTEXT direct write** (chosen) | Primary               | No focus dependency, no synthetic keystrokes, reliable cross-process within the same desktop session; automatable for acceptance. Works only for classic Win32 EDIT controls.                                                     |
| Clipboard relay (Ctrl+V)             | **Built, NOT wired**  | Helpers exist (`with_clipboard_paste` + `paste_into_focused`) but the production path never calls them — they are not an active fallback. Inherent limitation: the system clipboard is shared across the desktop session; any process can read the secret while it is parked there, so backup/restore only shrinks the exposure window and provides **no confidentiality**. Enabling it requires disclosing that boundary in the UI first. |
| UI Automation                        | Not built             | Covers self-drawn controls, but adds `Win32_UI_Accessibility` + COM lifetime management; recorded as future extension, not stubbed.                                                                                               |

## Field selection

`EnumChildWindows` over the target top-level window, keeping class `Edit`
controls. Eligibility per field: visible (`IsWindowVisible`), enabled
(`IsWindowEnabled`), not read-only (no `ES_READONLY`).

- password = first **eligible** `ES_PASSWORD`-styled edit — **mandatory**;
  no eligible password-styled field → the whole fill is **refused**;
- username = first eligible non-password edit (optional: a target without a
  usable username field gets a password-only fill, reported honestly);
- the old "second field" heuristic (plain edit as pseudo-password box) was
  **removed** in the 2026-11-06 security pass: any foreground process could
  arrange two plain edits and masquerade as a login form — plain edits are
  never treated as password fields.

## Target identity: fingerprint + user confirmation

The floating window's show path captures `GetForegroundWindow` **before** it
takes focus. The snapshot stores a **three-element fingerprint**: top-level
window class, the owning process's executable path, and the window title,
plus hwnd + pid. If the executable path cannot be queried, no target is
captured at all — no fingerprint, no trusted injection.

At fill time the fingerprint is revalidated: `IsWindow`, same pid (never our
own process), same window class, same executable path, and the title still
prefixed by the captured title (an empty snapshot title only matches an empty
current title). Each child control is revalidated **immediately before its
write**: alive, still owned by the captured root window, same pid, class
`Edit`, and style checks (the password box must still carry `ES_PASSWORD`;
visible/enabled/not-read-only for both fields).

Win32 checks are not atomic — a small race window between revalidation and
`SendMessageW` remains. The residual risk is mitigated by the **explicit
user confirmation gate**: the floating window shows the target app's
executable name and window title, and the fill command (`desktop_fill_credential`)
rejects any call without `confirmed = true`. There is no silent injection
path; a mis-identified target is visible to the user before Enter.

The ready state shown in the floating window reflects the *validated* state:
`fill_target_status` revalidates the slot (invalid targets are dropped
immediately), and hiding the quick access window discards the captured
target entirely.

## Secrets hygiene

- Username/password travel through the same decryption path as
  `reveal_credential_secret` (audit + re-auth gating); no new plaintext cache.
- WM_SETTEXT is the default path — the clipboard is not touched at all.
- The unwired clipboard relay helpers back up and restore prior clipboard
  content (panic-safe and `GlobalSize`-bounded since 2026-11-06); failures
  are surfaced as warnings, never silent — but per the boundary above they
  still expose plaintext to a session-global channel.

## Where the code lives

- `desktop/src-tauri/src/desktop_fill.rs` — engine + Windows integration tests
  (real windows with real EDIT controls, verified via WM_GETTEXT read-back).
- `desktop/src-tauri/fill-test/` — cross-process suite (test-only workspace
  member, `cargo test --features fill-test-host -p persona-fill-test
  --test desktop_fill_cross_process`):
  a separate target process (`fill-test-host` bin) is injected into; covers
  successful ES_PASSWORD injection, plain-edit-only rejection, same-title
  decoy-process rejection, and destroy/recreate race rejection. It must run
  in an interactive desktop session (SSH sessions report no visible windows
  and no foreground window). Platform note (measured on Windows Server 2022,
  2026-11-06): a cross-process `WM_GETTEXT`/`WM_GETTEXTLENGTH` on an
  `ES_PASSWORD` edit returns an empty string even after a successful
  cross-process `WM_SETTEXT` — the OS hides password text from other
  processes' read-back. The suite therefore verifies password injection via
  same-process read-back (`fill-test-host` `readback` command) plus
  cross-process `EM_GETPASSWORDCHAR`/style assertions; the plain-edit
  cross-process read-back assertion is unchanged.
- `desktop/src-tauri/src/quick_access.rs` — target capture hook in the
  floating-window toggle; hide/close discards the captured target.
- `commands::fill_target_status` / `commands::desktop_fill_credential` —
  the command layer (status revalidation + `confirmed` gate); the floating
  window binds ⌘F to the confirm-then-fill flow (i18n'd hints included).
