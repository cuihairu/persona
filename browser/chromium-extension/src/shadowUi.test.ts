import { mountPersonaUi, PERSONA_UI_HOST_ID } from './shadowUi';

describe('mountPersonaUi', () => {
    beforeEach(() => {
        document.body.innerHTML = '';
        document.head.innerHTML = '';
    });

    it('mounts a single host element on body and keeps the page otherwise clean', () => {
        const { host, root } = mountPersonaUi(document);
        expect(host.localName).toBe('persona-autofill-host');
        expect(document.body.children).toHaveLength(1);
        expect(document.body.children[0]).toBe(host);
        expect(root.host).toBe(host);
    });

    it('is idempotent while the host stays connected', () => {
        const first = mountPersonaUi(document);
        const second = mountPersonaUi(document);
        expect(second.host).toBe(first.host);
        expect(second.root).toBe(first.root);
        expect(document.body.children).toHaveLength(1);
    });

    it('remounts on a fresh host after the previous one is detached', () => {
        const first = mountPersonaUi(document);
        first.host.remove();
        const second = mountPersonaUi(document);
        expect(second.host).not.toBe(first.host);
        expect(second.root).not.toBe(first.root);
        expect(document.getElementById(PERSONA_UI_HOST_ID)).toBe(second.host);
    });

    it('uses a closed shadow root so page scripts cannot reach the widgets', () => {
        const { host } = mountPersonaUi(document);
        expect(host.shadowRoot).toBeNull();
    });

    it('ships the shared keyframes inside the shadow root, not document.head', () => {
        const { root } = mountPersonaUi(document);
        const styles = Array.from(root.querySelectorAll('style'));
        expect(styles.some((s) => (s.textContent ?? '').includes('persona-slide-in'))).toBe(true);
        expect(document.head.querySelectorAll('style')).toHaveLength(0);
    });

    it('stops clicks on Persona UI at the shadow root', () => {
        const { root } = mountPersonaUi(document);
        const docClick = jest.fn();
        document.addEventListener('click', docClick);
        try {
            const inner = document.createElement('div');
            root.appendChild(inner);
            inner.click();
            expect(docClick).not.toHaveBeenCalled();

            document.body.click();
            expect(docClick).toHaveBeenCalledTimes(1);
        } finally {
            document.removeEventListener('click', docClick);
        }
    });
});
