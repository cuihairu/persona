# Desktop Fill Injection (Windows)

One-liner: after the user picks a credential in the Quick Access floating window,
Persona injects username/password into the app that held the foreground **before**
the floating window appeared — the desktop-app sibling of the browser extension's
fill (FEATURE_GAP_ANALYSIS #12).

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
| Clipboard relay (Ctrl+V)             | Fallback, implemented | Backs apps that validate on keystroke events; clipboard is backed up before paste and restored right after, secret exposure window is the paste closure only. Not primary: cross-process focus fights the system foreground lock. |
| UI Automation                        | Not built             | Covers self-drawn controls, but adds `Win32_UI_Accessibility` + COM lifetime management; recorded as future extension, not stubbed.                                                                                               |

## Field selection

`EnumChildWindows` over the target top-level window, keeping class `Edit` controls:

- username = first non-password-styled edit;
- password = first `ES_PASSWORD`-styled edit;
- no password-styled field but ≥ 2 edits → second field heuristic;
- all fields password-styled (change-password dialogs) → refuse to inject.

## Target acquisition and revalidation

The floating window's show path captures `GetForegroundWindow` **before** it
takes focus (pid must differ from Persona's own). The snapshot (hwnd + title +
pid) lives in `AppState.fill_target`. At fill time the target is revalidated:
`IsWindow`, same pid, current title still prefixed by the captured title —
defending against HWND reuse. Invalid targets are dropped, and the user gets an
honest error.

## Secrets hygiene

- Username/password travel through the same decryption path as
  `reveal_credential_secret` (audit + re-auth gating); no new plaintext cache.
- Clipboard relay backs up and restores prior clipboard content; failures are
  surfaced as warnings, never silent.
- WM_SETTEXT is the default path — the clipboard is not touched at all.

## Where the code lives

- `desktop/src-tauri/src/desktop_fill.rs` — engine + Windows integration tests
  (real windows with real EDIT controls, verified via WM_GETTEXT read-back).
- `desktop/src-tauri/src/quick_access.rs` — target capture hook in the
  floating-window toggle.
- `commands::fill_target_status` / `commands::desktop_fill_credential` — the
  command layer; the floating window binds ⌘F to fill (i18n'd hints included).
