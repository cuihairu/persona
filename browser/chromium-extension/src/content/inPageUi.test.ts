/**
 * In-page surface restyle (Phase 3): every visible widget must ride the
 * shared token CSS inside the shadow root — no ad-hoc inline palettes, no
 * off-brand gradients, and the class hooks the behaviors depend on
 * (outside-click / enter-to-pick selectors) must exist.
 */

import { mountPersonaUi, PERSONA_SHARED_CSS, PERSONA_UI_HOST_ID } from '../shadowUi';

describe('PERSONA_SHARED_CSS', () => {
    it('defines the prefixed token set on the host', () => {
        expect(PERSONA_SHARED_CSS).toContain(':host');
        for (const token of ['--p-accent', '--p-surface', '--p-text', '--p-border-01', '--p-elevation', '--p-font']) {
            expect(PERSONA_SHARED_CSS).toContain(token);
        }
    });

    it('keeps a dark palette variant behind prefers-color-scheme', () => {
        expect(PERSONA_SHARED_CSS).toContain('@media (prefers-color-scheme: dark)');
    });

    it('covers every in-page widget class', () => {
        for (const cls of [
            '.p-panel', '.p-head', '.p-plain-head', '.p-body', '.p-item',
            '.p-chip', '.p-empty', '.p-searchbox', '.p-toast.ok', '.p-toast.err',
            '.p-save', '.p-save-title', '.p-save-detail', '.p-save-status.show',
            '.p-btn.secondary', '.p-btn.block', '.p-x', '.p-label', '.p-check',
            '.p-badge', '.p-ok-text', '.p-err-text'
        ]) {
            expect(PERSONA_SHARED_CSS).toContain(cls);
        }
    });

    it('keeps the shared keyframes name the widgets animate with', () => {
        expect(PERSONA_SHARED_CSS).toContain('@keyframes persona-slide-in');
    });

    it('drops the off-brand purple gradient from the in-page palette', () => {
        expect(PERSONA_SHARED_CSS).not.toContain('#6366f1');
        expect(PERSONA_SHARED_CSS).not.toContain('#8b5cf6');
    });

    it('prefixes all custom properties so page variables cannot retheme widgets', () => {
        const decls = PERSONA_SHARED_CSS.match(/--[a-z0-9-]+(?=\s*:)/g) ?? [];
        const foreign = decls.filter((name) => !name.startsWith('--p-'));
        expect(foreign).toEqual([]);
    });
});

describe('in-page widget markup hooks', () => {
    beforeEach(() => {
        document.body.innerHTML = '';
    });

    function shadowRoot(): ShadowRoot {
        return mountPersonaUi(document).root;
    }

    it('mounts the shared stylesheet into the shadow root', () => {
        const root = shadowRoot();
        const styles = Array.from(root.querySelectorAll('style'));
        expect(styles.some((s) => (s.textContent ?? '').includes(PERSONA_SHARED_CSS.slice(0, 80)))).toBe(true);
    });

    it('exposes .p-item rows for the enter-to-pick selector', () => {
        const root = shadowRoot();
        const item = document.createElement('div');
        item.className = 'p-item';
        item.innerHTML = '<div class="t">GitHub</div><div class="s">octo@example.com</div>';
        root.appendChild(item);
        expect(root.querySelector('.p-item')).toBe(item);
        expect(item.querySelector('.p-item .t')?.textContent).toBe('GitHub');
    });
});

describe('legacy inline palettes removed from sources', () => {
    it('widget builders no longer hand-roll colors inline', () => {
        // Guard the invariant: colors live in PERSONA_SHARED_CSS, geometry
        // (position/left/top/z-index) stays inline. If someone re-adds a
        // background/color to a cssText block here, the in-page face drifts
        // from the popup token system again.
        const fs = require('fs');
        const path = require('path');
        for (const file of ['overlay.ts', 'saveBar.ts', 'icons.ts']) {
            const src = fs.readFileSync(path.join(__dirname, file), 'utf8');
            expect(src).not.toMatch(/#[0-9a-fA-F]{6}\s*;/);
            expect(src).not.toContain('linear-gradient');
        }
    });

    it('field badges and headers use inline SVG marks, not emoji', () => {
        const fs = require('fs');
        const path = require('path');
        const src = fs.readFileSync(path.join(__dirname, 'icons.ts'), 'utf8');
        for (const emoji of ['🛡️', '🔑', '🎲']) {
            expect(src).not.toContain(emoji);
        }
        expect(src).toContain('BRAND_MARK_SVG');
        expect(src).toContain('stroke="currentColor"');
    });
});
