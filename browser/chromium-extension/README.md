# Persona Chromium Extension (Chrome / Edge)

This package hosts the browser extension that will power Persona's autofill, credential management,
TOTP display, and SSH-agent workflows in Chromium-based browsers. It is intentionally lightweight for now:

- `src/background.ts` hosts the service worker glue to the local Persona core/CLI.
- `src/formScanner.ts` contains heuristic form detection for passwords/usernames/TOTP.
- `src/content.ts` injects the scanner, streams snapshots to the background script, and listens for popup requests.
- `src/webauthnHook.ts` intercepts WebAuthn ceremonies in the MAIN world and routes them to Persona (v2 protocol).
- `src/nativeBridge.ts` implements the Native Messaging bridge to `persona bridge` (stdio JSON frames).
- `src/popup.ts` renders the popup UI, wires the “Connect” button, and displays detected form metadata.
- `manifest.json` is the loadable MV3 manifest (points at `dist/*` + `public/popup.html`).
- `public/manifest.json` is kept as a reference/template while the packaging flow evolves.

## Scripts

```
npm install
npm run build
```

Outputs are written to `dist/` and referenced from the static popup HTML. During active development we
will likely switch to Vite or another bundler, but keeping plain TypeScript reduces moving pieces until
we hook the extension to the desktop/client runtimes.

The popup supports both legacy HTTP probes (future) and Native Messaging endpoints via:

- `native:com.persona.native` (default)

When pairing is enabled (default), request a pairing code from the popup and approve it via:

`persona bridge --approve-code <CODE>`

TOTP/2FA support:

- Create a TOTP credential with an associated URL (e.g. `persona totp setup --identity <name> --url https://github.com ...`)
- On pages with 2FA inputs (e.g. GitHub), focus the code field and click the inline icon to fill the TOTP

Passkeys (WebAuthn, bridge protocol v2):

- `src/webauthnHook.ts` is injected into the `MAIN` world at `document_start` and wraps
  `navigator.credentials.create/get`. Persona never blocks the site's native flow: user cancel,
  no stored candidates, conditional mediation, and cross-origin iframes all fall back to the
  original browser implementation.
- `src/content.ts` runs the confirmation/selection UI in the ISOLATED world: creating a passkey
  requires an explicit confirm dialog; signing (assertion) shows a candidate picker where even a
  single candidate must be clicked (no silent signing).
- The `persona bridge` session unlocks with the master password, so the WebAuthn user-verified
  flag truthfully reflects local authentication. See `docs/PASSKEYS_DESIGN.md` and
  `docs/BRIDGE_PROTOCOL.md` (v2 messages `passkey_list` / `passkey_create` / `passkey_assert`).
- Chromium only. Safari does not support MAIN-world WebAuthn interception — that host shell waits
  for the OS passkey provider phase.

For Native Messaging host installation and protocol details, see:

- `scripts/native-messaging/install-native-host.sh`
- `scripts/native-messaging/install-native-host.ps1`
- `docs/BRIDGE_PROTOCOL.md`
