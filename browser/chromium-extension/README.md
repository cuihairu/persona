# Persona Chromium Extension (Chrome / Edge)

This package hosts the browser extension that will power Persona's autofill, credential management,
TOTP display, and SSH-agent workflows in Chromium-based browsers. It is intentionally lightweight for now:

- `src/background.ts` hosts the service worker glue to the local Persona core/CLI.
- `src/formScanner.ts` contains heuristic form detection for passwords/usernames/TOTP.
- `src/content.ts` injects the scanner, streams snapshots to the background script, and listens for popup requests.
- `src/bridge.ts` implements the HTTP probe against the Persona desktop/CLI bridge.
- `src/popup.ts` renders the popup UI, wires the “Connect” button, and displays detected form metadata.
- `public/manifest.json` declares MV3 permissions for scripting, storage, and action popup.

## Scripts

```
npm install
npm run build
```

Outputs are written to `dist/` and referenced from the static popup HTML. During active development we
will likely switch to Vite or another bundler, but keeping plain TypeScript reduces moving pieces until
we hook the extension to the desktop/client runtimes. The popup input allows overriding the bridge
endpoint so QA can point to staging builds of the forthcoming `persona bridge` command, and the form
panel (plus domain security warnings) surfaces the heuristics’ view of the active page before autofill ships.
