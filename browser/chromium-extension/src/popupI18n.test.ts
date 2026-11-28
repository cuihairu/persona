/**
 * Contract between the popup markup and the localization table: every entry
 * in POPUP_I18N finds its element in the REAL public/popup.html, every key
 * resolves in BOTH locale catalogs, and applying the table leaves no
 * placeholder-looking text behind. Chrome never substitutes __MSG_x__ in
 * HTML (only manifest + CSS), so this table is the only localization path
 * for the popup face.
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import { POPUP_I18N, applyPopupI18n, type PopupI18nEntry } from './popupI18n.js';

const root = join(__dirname, '..');

function catalog(locale: string): Record<string, { message: string }> {
    return JSON.parse(readFileSync(join(root, '_locales', locale, 'messages.json'), 'utf8'));
}

function realDom(): Document {
    const html = readFileSync(join(root, 'public', 'popup.html'), 'utf8');
    return new DOMParser().parseFromString(html, 'text/html');
}

describe('popup i18n table vs real markup', () => {
    it('every entry id exists in public/popup.html', () => {
        const doc = realDom();
        const result = applyPopupI18n(doc, POPUP_I18N, () => 'X');
        expect(result.missingElement).toEqual([]);
    });

    it('every entry key resolves in en and zh_CN', () => {
        const en = catalog('en');
        const zh = catalog('zh_CN');
        for (const entry of POPUP_I18N) {
            expect(en[entry.key]?.message).toBeTruthy();
            expect(zh[entry.key]?.message).toBeTruthy();
        }
    });

    it('applying en strings overwrites every static default', () => {
        const doc = realDom();
        const en = catalog('en');
        const fake = (key: string) => `X:${key}`;
        const result = applyPopupI18n(doc, POPUP_I18N, fake);
        expect(result.missingMessage).toEqual([]);
        const body = doc.body.textContent ?? '';
        expect(body).not.toMatch(/__MSG_/);
        const textEntries = POPUP_I18N.filter((e: PopupI18nEntry) => !e.attr);
        for (const entry of textEntries) {
            expect(doc.getElementById(entry.id)?.textContent).toBe(fake(entry.key));
        }
        const title = doc.getElementById('searchInput')?.getAttribute('placeholder');
        expect(title).toBe('X:popupSearchPlaceholder');
        // sanity: the table must not have silently drifted from the catalog
        expect(en[POPUP_I18N[0].key]?.message.length).toBeGreaterThan(0);
    });
});
