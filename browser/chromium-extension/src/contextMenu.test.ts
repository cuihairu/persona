import {
    MENU_COPY_PREFIX,
    MENU_FILL_PREFIX,
    MENU_POPUP_ID,
    MENU_ROOT_ID,
    MENU_SUGGESTION_CAP,
    buildMenuEntries,
    parseMenuAction,
    type MenuSuggestion
} from './contextMenu.js';

const SUGGESTIONS: MenuSuggestion[] = [
    { item_id: 'aaa', title: 'GitHub', credential_type: 'password' },
    { item_id: 'bbb', title: 'Mail auth', credential_type: 'totp' },
    { item_id: 'ccc', title: 'Visa', credential_type: 'bank_card' }
];

describe('buildMenuEntries', () => {
    it('opens with the root entry', () => {
        expect(buildMenuEntries([])[0]).toEqual({ id: MENU_ROOT_ID, title: 'Persona' });
    });

    it('always ends with the open-popup entry under the root', () => {
        const entries = buildMenuEntries([]);
        expect(entries[entries.length - 1]).toEqual({ id: MENU_POPUP_ID, title: 'Open Persona popup', parentId: MENU_ROOT_ID });
    });

    it('emits fill and copy children for password suggestions', () => {
        const entries = buildMenuEntries([SUGGESTIONS[0]]);
        expect(entries.slice(1)).toEqual([
            { id: `${MENU_FILL_PREFIX}password:aaa`, title: 'Fill: GitHub', parentId: MENU_ROOT_ID },
            { id: `${MENU_COPY_PREFIX}password:aaa`, title: 'Copy password: GitHub', parentId: MENU_ROOT_ID },
            { id: MENU_POPUP_ID, title: 'Open Persona popup', parentId: MENU_ROOT_ID }
        ]);
    });

    it('labels 2FA suggestions as code entries', () => {
        const entries = buildMenuEntries([SUGGESTIONS[1]]);
        expect(entries[1].title).toBe('Fill 2FA code: Mail auth');
        expect(entries[2].title).toBe('Copy 2FA code: Mail auth');
    });

    it('gives card suggestions a fill entry but no copy entry', () => {
        const entries = buildMenuEntries([SUGGESTIONS[2]]);
        expect(entries[1].title).toBe('Fill: Visa');
        expect(entries.some((e) => e.id.startsWith(MENU_COPY_PREFIX))).toBe(false);
    });

    it('caps the suggestion pool and always keeps the popup entry', () => {
        const many: MenuSuggestion[] = Array.from({ length: MENU_SUGGESTION_CAP + 4 }, (_, i) => ({
            item_id: `id-${i}`,
            title: `Item ${i}`
        }));
        const entries = buildMenuEntries(many);
        const fillEntries = entries.filter((e) => e.id.startsWith(MENU_FILL_PREFIX));
        expect(fillEntries).toHaveLength(MENU_SUGGESTION_CAP);
        expect(entries[entries.length - 1]?.id).toBe(MENU_POPUP_ID);
    });

    it('treats unknown credential types as logins', () => {
        const entries = buildMenuEntries([{ item_id: 'zzz', title: 'Odd' }]);
        expect(entries[1].title).toBe('Fill: Odd');
        expect(entries[2].title).toBe('Copy password: Odd');
    });
});

describe('parseMenuAction', () => {
    it('decodes fill entries back to kind and item', () => {
        expect(parseMenuAction(`${MENU_FILL_PREFIX}password:aaa`)).toEqual({ action: 'fill', kind: 'password', itemId: 'aaa' });
        expect(parseMenuAction(`${MENU_FILL_PREFIX}totp:bbb`)).toEqual({ action: 'fill', kind: 'totp', itemId: 'bbb' });
        expect(parseMenuAction(`${MENU_FILL_PREFIX}card:ccc`)).toEqual({ action: 'fill', kind: 'card', itemId: 'ccc' });
    });

    it('decodes copy entries to password and totp only', () => {
        expect(parseMenuAction(`${MENU_COPY_PREFIX}password:aaa`)).toEqual({ action: 'copy', kind: 'password', itemId: 'aaa' });
        expect(parseMenuAction(`${MENU_COPY_PREFIX}totp:bbb`)).toEqual({ action: 'copy', kind: 'totp', itemId: 'bbb' });
        expect(parseMenuAction(`${MENU_COPY_PREFIX}card:ccc`)).toBeNull();
    });

    it('round-trips builder ids', () => {
        for (const entry of buildMenuEntries(SUGGESTIONS)) {
            if (entry.id === MENU_ROOT_ID || entry.id === MENU_POPUP_ID) continue;
            expect(parseMenuAction(entry.id)).not.toBeNull();
        }
    });

    it('rejects malformed or foreign ids', () => {
        expect(parseMenuAction(MENU_ROOT_ID)).toBeNull();
        expect(parseMenuAction(MENU_POPUP_ID)).toEqual({ action: 'popup' });
        expect(parseMenuAction(`${MENU_FILL_PREFIX}card-only-no-sep`)).toBeNull();
        expect(parseMenuAction('other-extension-entry')).toBeNull();
    });
});
