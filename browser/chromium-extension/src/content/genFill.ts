/**
 * Generated-password fill-into-page: the popup generates a password and can
 * hand it to the content script to write into a password field of the page
 * the user is signing up on. Target selection prefers the password input the
 * user focused last (tracked on focusin); if it navigated away, fall back to
 * the first usable password input still in the document. Password fields
 * only — 1Password semantics: generated passwords belong in password boxes,
 * andOTP digit groups are type=text/number and never match.
 */

import { fillInput } from './util.js';
import { state } from './state.js';

/** True for the inputs generated passwords may go into. */
export function isPasswordLikeInput(el: EventTarget | null): el is HTMLInputElement {
    return el instanceof HTMLInputElement && el.type === 'password';
}

/** focusin side: remember the most recent password-like field. */
export function trackPasswordFocus(event: Event): void {
    trackPasswordTarget(event.target);
}

export function trackPasswordTarget(target: EventTarget | null): void {
    if (isPasswordLikeInput(target)) {
        state.lastPasswordInput = target;
    }
}

/**
 * Resolve the fill target: the tracked input while it is still attached,
 * else the first usable (enabled, non-readonly) password input in the
 * document. Visibility is deliberately not a criterion — hidden password
 * fields (reveal toggles, multi-step forms) are still valid destinations.
 */
export function pickGeneratedFillTarget(): HTMLInputElement | null {
    const tracked = state.lastPasswordInput;
    if (tracked && tracked.isConnected) return tracked;
    const candidates = document.querySelectorAll<HTMLInputElement>('input[type="password"]');
    for (const el of candidates) {
        if (!el.disabled && !el.readOnly) return el;
    }
    return null;
}

/** Write the generated password into the resolved target. False = no target. */
export function fillGeneratedPassword(value: string): boolean {
    if (!value) return false;
    const target = pickGeneratedFillTarget();
    if (!target) return false;
    fillInput(target, value);
    return true;
}
