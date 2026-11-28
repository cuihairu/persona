/**
 * inlineMenu tests: field classification, trigger verdicts (settings,
 * domain, pool, session repeat, debounce), field keys, candidate picking.
 */

import {
    candidateKindForField,
    classifyInlineMenuField,
    makeInlineMenuFieldKey,
    pickInlineMenuCandidates,
    shouldShowInlineMenu
} from './inlineMenu.js';

const okBase = {
    fieldKind: 'password' as const,
    inlineMenuOnFocus: true,
    domainAllowed: true,
    suggestionCount: 3,
    fieldKey: 'form|user|password',
    shownKeys: new Set<string>(),
    now: 10000,
    lastMenuAt: 0,
    debounceMs: 800
};

describe('classifyInlineMenuField', () => {
    it('sorts password, totp and identity fields', () => {
        expect(classifyInlineMenuField({ inputType: 'password', name: 'pw', id: '', autocomplete: '' })).toBe('password');
        expect(classifyInlineMenuField({ inputType: 'text', name: 'user', id: '', autocomplete: '' })).toBe('identity');
        expect(classifyInlineMenuField({ inputType: 'email', name: '', id: 'mail', autocomplete: '' })).toBe('identity');
        expect(classifyInlineMenuField({ inputType: 'text', name: '', id: '', autocomplete: 'username' })).toBe('identity');
    });

    it('detects totp via autocomplete, name hints, numeric length and aria', () => {
        expect(classifyInlineMenuField({ inputType: 'text', name: 'otp', id: '', autocomplete: '' })).toBe('totp');
        expect(classifyInlineMenuField({ inputType: 'text', name: '', id: '', autocomplete: 'one-time-code' })).toBe('totp');
        expect(
            classifyInlineMenuField({ inputType: 'text', name: '', id: '', autocomplete: '', inputMode: 'numeric', maxLength: 6 })
        ).toBe('totp');
        expect(
            classifyInlineMenuField({ inputType: 'text', name: '', id: '', autocomplete: '', ariaLabel: 'verification code' })
        ).toBe('totp');
    });

    it('returns null for non-menu fields', () => {
        expect(classifyInlineMenuField({ inputType: 'checkbox', name: 'agree', id: '', autocomplete: '' })).toBeNull();
        expect(classifyInlineMenuField({ inputType: 'search', name: 'q', id: '', autocomplete: '' })).toBeNull();
        expect(classifyInlineMenuField({ inputType: 'tel', name: 'phone', id: '', autocomplete: '' })).toBeNull();
    });
});

describe('shouldShowInlineMenu', () => {
    it('shows when every gate passes', () => {
        expect(shouldShowInlineMenu(okBase)).toEqual({ show: true, reason: 'ok' });
    });

    it('gates in order: field → setting → domain → pool → repeat → debounce', () => {
        expect(shouldShowInlineMenu({ ...okBase, fieldKind: null }).reason).toBe('not-menu-field');
        expect(shouldShowInlineMenu({ ...okBase, inlineMenuOnFocus: false }).reason).toBe('setting-off');
        expect(shouldShowInlineMenu({ ...okBase, domainAllowed: false }).reason).toBe('domain-blocked');
        expect(shouldShowInlineMenu({ ...okBase, suggestionCount: 0 }).reason).toBe('empty-pool');
        expect(
            shouldShowInlineMenu({ ...okBase, shownKeys: new Set(['form|user|password']) }).reason
        ).toBe('repeat');
        expect(shouldShowInlineMenu({ ...okBase, lastMenuAt: 9500 }).reason).toBe('debounced');
    });

    it('debounce is a sliding window, not a repeat-suppressor', () => {
        // past the window the same field can re-offer if it was never shown
        expect(shouldShowInlineMenu({ ...okBase, lastMenuAt: 9100 }).reason).toBe('ok');
        expect(shouldShowInlineMenu({ ...okBase, lastMenuAt: 9201 }).reason).toBe('debounced');
    });
});

describe('makeInlineMenuFieldKey', () => {
    it('prefers name over id and keeps form scope', () => {
        expect(makeInlineMenuFieldKey({ formId: 'login', name: 'user', id: 'u1', inputType: 'text' })).toBe('login|user|text');
        expect(makeInlineMenuFieldKey({ formId: null, name: '', id: 'u1', inputType: 'text' })).toBe('|u1|text');
        expect(makeInlineMenuFieldKey({ name: '', id: '', inputType: 'password' })).toBe('||password');
    });
});

describe('pickInlineMenuCandidates', () => {
    const pool = [
        { item_id: 'a', title: 'A', match_strength: 95, credential_type: 'password' },
        { item_id: 'b', title: 'B', match_strength: 60, credential_type: 'password' },
        { item_id: 'c', title: 'C', match_strength: 99, credential_type: 'password' },
        { item_id: 'd', title: 'D', match_strength: 90, credential_type: 'totp' },
        { item_id: 'e', title: 'E', match_strength: 97 }, // missing type = password
        { item_id: 'f', title: 'F', match_strength: 20, credential_type: 'password' }
    ];

    it('filters by kind, applies the strength floor, sorts strongest first', () => {
        const out = pickInlineMenuCandidates(pool, 'password', 90);
        expect(out.map((s) => s.item_id)).toEqual(['c', 'e', 'a']);
        const totp = pickInlineMenuCandidates(pool, 'totp', 90);
        expect(totp.map((s) => s.item_id)).toEqual(['d']);
    });

    it('caps the list so a big vault cannot blow the menu height', () => {
        const many = Array.from({ length: 30 }, (_, i) => ({
            item_id: `i${i}`,
            title: `I${i}`,
            match_strength: 100 - i,
            credential_type: 'password'
        }));
        expect(pickInlineMenuCandidates(many, 'password', 0)).toHaveLength(8);
        expect(pickInlineMenuCandidates(many, 'password', 0)[0].item_id).toBe('i0');
    });

    it('keeps only above-floor items and empty for an empty pool', () => {
        expect(pickInlineMenuCandidates(pool, 'password', 96).map((s) => s.item_id)).toEqual(['c', 'e']);
        expect(pickInlineMenuCandidates(pool, 'password', 98).map((s) => s.item_id)).toEqual(['c']);
        expect(pickInlineMenuCandidates([], 'password', 0)).toEqual([]);
    });
});

describe('candidateKindForField', () => {
    it('maps identity and password fields to logins, totp to codes', () => {
        expect(candidateKindForField('identity')).toBe('password');
        expect(candidateKindForField('password')).toBe('password');
        expect(candidateKindForField('totp')).toBe('totp');
    });
});
