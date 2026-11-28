/**
 * inlineMenuUi tests (jsdom): positioning with viewport flip, listbox
 * semantics (roles, aria-activedescendant), keyboard navigation, pick
 * paths (click/Enter) and the close rules (Escape/scroll/blur/outside).
 */

import { computeMenuPosition, renderInlineMenu } from './inlineMenuUi.js';
import type { InlineCandidate } from './inlineMenu.js';

const field = { top: 200, bottom: 224, left: 40, height: 24 };

describe('computeMenuPosition', () => {
    const viewport = { innerWidth: 800, innerHeight: 600 };
    const menu = { width: 280, height: 200 };

    it('prefers below the field', () => {
        const pos = computeMenuPosition(field, menu, viewport);
        expect(pos.placement).toBe('below');
        expect(pos.top).toBe(field.bottom + 4);
        expect(pos.left).toBe(field.left);
    });

    it('flips above when below overflows and there is more room above', () => {
        const lowField = { top: 500, bottom: 524, left: 40, height: 24 };
        const pos = computeMenuPosition(lowField, menu, viewport);
        expect(pos.placement).toBe('above');
        expect(pos.top).toBe(lowField.top - 4 - menu.height);
    });

    it('stays below when neither side truly fits (top edge), clamped', () => {
        const tallMenu = { width: 280, height: 500 };
        const midField = { top: 300, bottom: 324, left: 40, height: 24 };
        const pos = computeMenuPosition(midField, tallMenu, viewport);
        expect(pos.placement).toBe('below');
        expect(pos.top).toBe(600 - 500);
    });

    it('clamps horizontal overflow into the viewport', () => {
        const rightField = { top: 100, bottom: 124, left: 700, height: 24 };
        const pos = computeMenuPosition(rightField, menu, viewport);
        expect(pos.left).toBe(800 - 280);
    });
});

describe('renderInlineMenu', () => {
    const candidates: InlineCandidate[] = [
        { item_id: 'a', title: 'Alpha', username_hint: 'a@x.io', match_strength: 95 },
        { item_id: 'b', title: 'Beta', match_strength: 80 },
        { item_id: 'c', title: 'Gamma', username_hint: 'g@x.io', match_strength: 70 }
    ];

    function mount() {
        document.body.innerHTML = '';
        const input = document.createElement('input');
        input.type = 'password';
        document.body.appendChild(input);
        const picked: InlineCandidate[] = [];
        const handle = renderInlineMenu(candidates, {
            field: { top: 100, bottom: 124, left: 10, height: 24 },
            mount: document.body,
            fieldEl: input,
            onPick: (c) => picked.push(c)
        });
        return { input, picked, handle };
    }

    const key = (key: string) =>
        new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true });

    it('renders a listbox with per-option ids and header', () => {
        const { handle } = mount();
        expect(handle.el.getAttribute('role')).toBe('listbox');
        const options = handle.el.querySelectorAll('[role="option"]');
        expect(options).toHaveLength(3);
        expect(options[0].id).toBe('persona-inline-opt-0');
        expect(options[0].querySelector('.t')?.textContent).toBe('Alpha');
        expect(options[1].querySelector('.s')?.textContent).toBe('');
        expect(handle.selectedIndex()).toBe(-1);
        handle.close();
    });

    it('arrow navigation updates aria-activedescendant and wraps', () => {
        const { handle } = mount();
        document.dispatchEvent(key('ArrowDown'));
        expect(handle.selectedIndex()).toBe(0);
        expect(handle.el.getAttribute('aria-activedescendant')).toBe('persona-inline-opt-0');
        expect(handle.el.querySelector('#persona-inline-opt-0')?.getAttribute('aria-selected')).toBe('true');
        document.dispatchEvent(key('ArrowDown'));
        document.dispatchEvent(key('ArrowDown'));
        expect(handle.selectedIndex()).toBe(2);
        document.dispatchEvent(key('ArrowDown'));
        expect(handle.selectedIndex()).toBe(0); // wraps
        document.dispatchEvent(key('ArrowUp'));
        expect(handle.selectedIndex()).toBe(2); // wraps backwards
        handle.close();
    });

    it('Enter picks the selected candidate and closes', () => {
        const { picked, handle } = mount();
        document.dispatchEvent(key('ArrowDown'));
        document.dispatchEvent(key('ArrowDown'));
        document.dispatchEvent(key('Enter'));
        expect(picked.map((c) => c.item_id)).toEqual(['b']);
        expect(handle.el.isConnected).toBe(false);
    });

    it('clicking an option picks it', () => {
        const { picked, handle } = mount();
        handle.el.querySelector<HTMLElement>('#persona-inline-opt-2')!.click();
        expect(picked.map((c) => c.item_id)).toEqual(['c']);
        expect(handle.el.isConnected).toBe(false);
    });

    it('closes on Escape and on scroll', () => {
        const { handle } = mount();
        document.dispatchEvent(key('Escape'));
        expect(handle.el.isConnected).toBe(false);

        const second = mount();
        document.dispatchEvent(new Event('scroll', { bubbles: true }));
        expect(second.handle.el.isConnected).toBe(false);
    });

    it('closes when the field blurs without pointer hover', () => {
        jest.useFakeTimers();
        try {
            const { input, handle } = mount();
            input.dispatchEvent(new FocusEvent('blur'));
            jest.advanceTimersByTime(200);
            expect(handle.el.isConnected).toBe(false);
        } finally {
            jest.useRealTimers();
        }
    });

    it('keyboard events are swallowed by the menu (no page scroll)', () => {
        const { handle } = mount();
        const evt = key('ArrowDown');
        const spy = jest.spyOn(evt, 'preventDefault');
        document.dispatchEvent(evt);
        expect(spy).toHaveBeenCalled();
        handle.close();
    });

    it('non-nav keys pass through untouched', () => {
        const { handle } = mount();
        const evt = key('a');
        const spy = jest.spyOn(evt, 'preventDefault');
        document.dispatchEvent(evt);
        expect(spy).not.toHaveBeenCalled();
        expect(handle.selectedIndex()).toBe(-1);
        handle.close();
    });
});
