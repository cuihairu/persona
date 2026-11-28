// Shadow-DOM isolation for every widget the content script injects into the
// page. All Persona UI lives inside one closed shadow root mounted on a
// single custom-element host, so:
//   - page scripts cannot reach the widgets' DOM (closed mode: `host.shadowRoot`
//     is null to everyone but this module),
//   - page CSS cannot restyle them (selectors don't cross the shadow boundary;
//     our shared keyframes live inside the root instead of document.head),
//   - clicks inside our UI are stopped at the shadow root, so page-level
//     "close on outside click" handlers only ever see real outside clicks.
// The host itself remains visible to page scripts (its id/localName can be
// observed), but its contents do not — same exposure class as the native
// host name and the existing content-script banner. Lookup never goes
// through the id: page markup could spoof `<persona-autofill-host>`, so we
// track the live host in module state and remount when it gets detached.

export const PERSONA_UI_HOST_ID = 'persona-autofill-host';

/**
 * Tokens + component classes shared by every in-page widget, mirroring the
 * popup stylesheet (same tiered borders, ring+shadow elevation, light/dark).
 * All custom properties carry the --p- prefix: custom properties inherit
 * across the shadow boundary, so page-level variables must not be able to
 * retheme our widgets by coincidence. (The host element itself is still
 * styleable by page CSS — cosmetic exposure only; the closed root keeps
 * structure and content unreadable.)
 * Kept here instead of document.head: a <style> in the page head was the
 * one true global stylesheet leak of the pre-shadow implementation.
 */
export const PERSONA_SHARED_CSS = `
@keyframes persona-slide-in {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

:host {
  --p-accent: hsl(214, 65%, 47%);
  --p-accent-bright: hsl(214, 75%, 56%);
  --p-accent-tint: hsla(214, 65%, 47%, 0.12);
  --p-accent-readable: hsl(214, 40%, 38%);
  --p-surface: hsl(0, 0%, 100%);
  --p-surface-alt: hsl(220, 20%, 94%);
  --p-text: hsl(222, 28%, 16%);
  --p-text-sub: hsl(220, 12%, 44%);
  --p-border-01: hsl(220, 16%, 91%);
  --p-border-02: hsl(220, 14%, 84%);
  --p-border-focus: hsla(214, 80%, 55%, 0.45);
  --p-ok: hsl(152, 55%, 38%);
  --p-danger: hsl(0, 62%, 48%);
  --p-radius: 10px;
  --p-radius-sm: 6px;
  --p-elevation: 0 0 0 1px var(--p-border-01), 0 8px 24px hsla(220, 40%, 20%, 0.16);
  --p-font: 13px/1.45 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

@media (prefers-color-scheme: dark) {
  :host {
    --p-accent: hsl(214, 80%, 62%);
    --p-accent-bright: hsl(214, 90%, 70%);
    --p-accent-tint: hsla(214, 80%, 62%, 0.16);
    --p-accent-readable: hsl(214, 45%, 72%);
    --p-surface: hsl(222, 18%, 16%);
    --p-surface-alt: hsl(222, 16%, 20%);
    --p-text: hsl(220, 25%, 90%);
    --p-text-sub: hsl(220, 12%, 62%);
    --p-border-01: hsl(222, 14%, 24%);
    --p-border-02: hsl(222, 12%, 30%);
    --p-border-focus: hsla(214, 90%, 65%, 0.5);
    --p-ok: hsl(152, 60%, 50%);
    --p-danger: hsl(0, 70%, 60%);
    --p-elevation: 0 0 0 1px hsla(220, 30%, 40%, 0.25), 0 8px 24px hsla(0, 0%, 0%, 0.5);
  }
}

/* floating panels (suggestion dropdown, search modal, generator dropdown) */
.p-panel {
  background: var(--p-surface);
  color: var(--p-text);
  border-radius: var(--p-radius);
  box-shadow: var(--p-elevation);
  font: var(--p-font);
  overflow: hidden;
}

.p-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  padding: 11px 14px;
  background: var(--p-accent);
  color: hsl(0, 0%, 100%);
  font-weight: 600;
}

.p-head .p-title { display: flex; align-items: center; gap: 8px; }

/* plain header for field-adjacent menus (no accent band) */
.p-plain-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 11px 14px;
  border-bottom: 1px solid var(--p-border-01);
  font-weight: 600;
  color: var(--p-text);
}

.p-check { display: flex; align-items: center; gap: 8px; }

.p-ok-text { color: var(--p-ok) !important; }
.p-err-text { color: var(--p-danger) !important; }

.p-body { max-height: 400px; overflow-y: auto; }

.p-item {
  padding: 11px 14px;
  cursor: pointer;
  border-top: 1px solid var(--p-border-01);
}

.p-item:hover { background: var(--p-surface-alt); }
/* keyboard-active item of the inline menu (aria-activedescendant target):
   distinct from the grey hover so the two highlight sources don't blur */
.p-item-active { background: var(--p-accent-tint); }
.p-item .t { font-weight: 600; }
.p-item .s {
  font-size: 12px;
  color: var(--p-text-sub);
  margin-top: 2px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.p-chip {
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.04em;
  background: var(--p-accent-tint);
  color: var(--p-accent-readable);
  padding: 2px 6px;
  border-radius: 4px;
}

.p-empty { padding: 24px; text-align: center; color: var(--p-text-sub); }

.p-searchbox {
  flex: 1;
  padding: 8px 12px;
  border: 1px solid var(--p-border-02);
  border-radius: var(--p-radius-sm);
  font: inherit;
  outline: none;
  background: var(--p-surface-alt);
  color: var(--p-text);
  min-width: 0;
}

.p-searchbox:focus-visible {
  border-color: var(--p-border-focus);
  box-shadow: 0 0 0 2px var(--p-border-focus);
}

.p-x {
  background: none;
  border: none;
  color: currentColor;
  cursor: pointer;
  font-size: 18px;
  line-height: 1;
  padding: 2px 6px;
}

/* toasts */
.p-toast {
  position: fixed;
  bottom: 20px;
  right: 20px;
  padding: 11px 16px;
  border-radius: var(--p-radius-sm);
  color: hsl(0, 0%, 100%);
  z-index: 2147483647;
  font: var(--p-font);
  box-shadow: var(--p-elevation);
  animation: persona-slide-in 0.25s ease;
}

.p-toast.ok { background: var(--p-ok); }
.p-toast.err { background: var(--p-danger); }

/* save bar */
.p-save {
  position: fixed;
  right: 16px;
  bottom: 16px;
  z-index: 2147483647;
  width: 320px;
  background: var(--p-surface);
  border: 1px solid var(--p-border-01);
  border-radius: var(--p-radius);
  box-shadow: var(--p-elevation);
  padding: 14px;
  font: var(--p-font);
  color: var(--p-text);
}

.p-save-title { font-weight: 600; margin-bottom: 4px; display: flex; align-items: center; gap: 6px; }
.p-save-detail { color: var(--p-text-sub); margin-bottom: 10px; word-break: break-all; }
.p-row { display: flex; gap: 8px; align-items: center; }
.p-save-status { margin-top: 8px; color: var(--p-text-sub); display: none; }
.p-save-status.show { display: block; }

.p-btn {
  padding: 7px 14px;
  border: none;
  border-radius: var(--p-radius-sm);
  background: var(--p-accent);
  color: hsl(0, 0%, 100%);
  cursor: pointer;
  font: inherit;
  font-weight: 600;
}

.p-btn:hover { background: var(--p-accent-bright); }
.p-btn:disabled { opacity: 0.45; cursor: not-allowed; }

.p-btn.secondary {
  background: var(--p-surface-alt);
  color: var(--p-text);
  border: 1px solid var(--p-border-02);
  font-weight: 500;
}

.p-btn.secondary:hover { background: var(--p-border-01); }
.p-btn.block { width: 100%; border-radius: 0; }

.p-label { display: block; margin-bottom: 8px; font-size: 12.5px; color: var(--p-text-sub); }

.p-input {
  width: 100%;
  padding: 6px 8px;
  border: 1px solid var(--p-border-02);
  border-radius: var(--p-radius-sm);
  font: inherit;
  background: var(--p-surface);
  color: var(--p-text);
  outline: none;
}

.p-input:focus-visible { border-color: var(--p-border-focus); box-shadow: 0 0 0 2px var(--p-border-focus); }

.p-sep { height: 1px; background: var(--p-border-01); margin: 8px 0; }

.p-pad { padding: 12px 14px; }

/* field badges (inline autofill / generator icons) */
.p-badge {
  position: absolute;
  width: 24px;
  height: 24px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  background: var(--p-surface);
  border: 1px solid var(--p-border-02);
  border-radius: var(--p-radius-sm);
  box-shadow: 0 1px 4px hsla(220, 40%, 20%, 0.18);
  color: var(--p-accent-readable);
  z-index: 999999;
}

.p-badge:hover { border-color: var(--p-accent); }

/* Motion-sensitive operators: keep the entrance but skip the slide. */
@media (prefers-reduced-motion: reduce) {
  .p-toast { animation: none; }
  .p-btn { transition: none; }
}

/* Keyboard focus must stay visible on every interactive surface. */
.p-item:focus-visible,
.p-btn:focus-visible,
.p-x:focus-visible,
.p-badge:focus-visible,
.p-check input:focus-visible {
  outline: none;
  border-color: var(--p-border-focus);
  box-shadow: 0 0 0 2px var(--p-border-focus);
}
`;

const SHARED_CSS = PERSONA_SHARED_CSS;

export interface PersonaUiSurface {
    host: HTMLElement;
    root: ShadowRoot;
}

let cached: PersonaUiSurface | null = null;

// Mount (or reuse) the single closed shadow root that hosts all Persona UI.
export function mountPersonaUi(doc: Document): PersonaUiSurface {
    if (cached && cached.host.isConnected) {
        return cached;
    }

    const host = doc.createElement('persona-autofill-host');
    host.id = PERSONA_UI_HOST_ID;
    // display:contents keeps the host layout- and stacking-transparent:
    // absolutely-positioned widgets still resolve their containing block
    // against body/html exactly as before, and their own z-index values keep
    // ordering against the page as they did when appended directly. The
    // !important guards the transparency against page CSS overrides.
    host.style.setProperty('display', 'contents', 'important');
    doc.body.appendChild(host);

    const root = host.attachShadow({ mode: 'closed' });
    const style = doc.createElement('style');
    style.textContent = SHARED_CSS;
    root.appendChild(style);

    // Clicks on Persona UI must not reach page listeners: the dropdown's own
    // "close on outside click" logic treats any document click outside the
    // dropdown as external, and under a closed shadow the event target is
    // retargeted to the host — so without this stop, clicking our own UI
    // would close it. Stopping here also keeps page scripts from reacting to
    // interactions with our widgets at all (bubble phase).
    root.addEventListener('click', (e) => e.stopPropagation());

    cached = { host, root };
    return cached;
}
