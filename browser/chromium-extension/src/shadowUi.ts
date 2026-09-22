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

// Animation shared by widgets inside the root. Kept here instead of
// document.head: a <style> in the page head was the one true global
// stylesheet leak of the pre-shadow implementation.
const SHARED_CSS = `
@keyframes persona-slide-in {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}
`;

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
