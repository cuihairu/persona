/**
 * Locale contract: every string referenced from shipping code or markup
 * resolves in BOTH locales, and the two catalogs stay key-aligned. A missing
 * key renders as a literal __MSG_key__ on screen (markup) or an empty string
 * (JS), so the contract test is the only line of defense.
 */

import { readFileSync } from 'fs';
import { join } from 'path';

interface Messages {
    [key: string]: { message: string };
}

function catalog(locale: string): Messages {
    return JSON.parse(readFileSync(join(__dirname, '..', '_locales', locale, 'messages.json'), 'utf8'));
}

function usedKeys(source: string, pattern: RegExp): string[] {
    return Array.from(source.matchAll(pattern)).map((m) => m[1]);
}

const en = catalog('en');
const zh = catalog('zh_CN');

describe('locale catalogs', () => {
    it('en and zh_CN define the same key set', () => {
        expect(Object.keys(zh).sort()).toEqual(Object.keys(en).sort());
    });

    it('every message body is a non-empty string', () => {
        for (const [locale, cat] of [['en', en], ['zh_CN', zh]] as const) {
            for (const [key, entry] of Object.entries(cat)) {
                expect(typeof entry.message).toBe('string');
                expect(entry.message.length).toBeGreaterThan(0);
            }
        }
    });
});

describe('referenced keys resolve', () => {
    const root = join(__dirname, '..');

    it('every getMessage key in the save bar and overlay exists in both locales', () => {
        for (const file of ['src/content/saveBar.ts', 'src/content/overlay.ts']) {
            const src = readFileSync(join(root, file), 'utf8');
            for (const key of usedKeys(src, /chrome\.i18n\.getMessage\('([A-Za-z0-9_]+)'\)/g)) {
                expect(en[key]).toBeDefined();
                expect(zh[key]).toBeDefined();
            }
        }
    });

    it('popup.html carries no __MSG_x__ placeholders at all', () => {
        // Chrome substitutes placeholders in manifest.json and CSS only; in
        // HTML pages they render as literal __MSG_...__ (verified live
        // 2026-11-28). Markup ships en defaults; popupI18n.ts applies the
        // locale strings via getMessage, and popupI18n.test.ts pins that
        // table against this markup.
        const html = readFileSync(join(root, 'public', 'popup.html'), 'utf8');
        expect(html).not.toMatch(/__MSG_[A-Za-z0-9_]+__/);
    });

    it('manifest declares the en default locale', () => {
        const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
        expect(manifest.default_locale).toBe('en');
    });
});
