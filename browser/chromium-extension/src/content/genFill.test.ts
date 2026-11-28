/**
 * genFill tests (jsdom): focus tracking, target resolution (tracked-first
 * with detached fallback), and the fill write (value + input/change events).
 */

import { fillGeneratedPassword, isPasswordLikeInput, pickGeneratedFillTarget, trackPasswordTarget } from './genFill.js';
import { state } from './state.js';

function pwField(): HTMLInputElement {
    const el = document.createElement('input');
    el.type = 'password';
    document.body.appendChild(el);
    return el;
}

describe('genFill', () => {
    beforeEach(() => {
        document.body.innerHTML = '';
        state.lastPasswordInput = null;
    });

    it('tracks only password-like focused inputs', () => {
        const password = pwField();
        const text = document.createElement('input');
        text.type = 'text';
        document.body.appendChild(text);
        trackPasswordTarget(text);
        expect(state.lastPasswordInput).toBeNull();
        trackPasswordTarget(password);
        expect(state.lastPasswordInput).toBe(password);
        expect(isPasswordLikeInput(password)).toBe(true);
        expect(isPasswordLikeInput(text)).toBe(false);
        expect(isPasswordLikeInput(document.body)).toBe(false);
    });

    it('prefers the tracked connected input, falls back to first usable', () => {
        const first = pwField();
        trackPasswordTarget(first);
        expect(pickGeneratedFillTarget()).toBe(first);

        // tracked node removed by navigation: fall back to another field,
        // skipping disabled/readonly ones
        const disabled = pwField();
        disabled.disabled = true;
        const readonly = pwField();
        readonly.readOnly = true;
        const usable = pwField();
        first.remove();
        expect(pickGeneratedFillTarget()).toBe(usable);
    });

    it('fillGeneratedPassword writes the value and fires input/change', () => {
        const target = pwField();
        trackPasswordTarget(target);
        const events: string[] = [];
        target.addEventListener('input', () => events.push('input'));
        target.addEventListener('change', () => events.push('change'));
        expect(fillGeneratedPassword('gen-9f2a!')).toBe(true);
        expect(target.value).toBe('gen-9f2a!');
        expect(events).toEqual(['input', 'change']);
    });

    it('fillGeneratedPassword reports failure without any target', () => {
        expect(fillGeneratedPassword('gen-9f2a!')).toBe(false);
        const detached = pwField();
        trackPasswordTarget(detached);
        detached.remove();
        expect(fillGeneratedPassword('gen-9f2a!')).toBe(false);
        expect(fillGeneratedPassword('')).toBe(false);
    });
});
