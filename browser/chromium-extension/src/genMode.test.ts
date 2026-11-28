/**
 * genMode tests: mode normalization and per-mode wire request assembly
 * (native protocol bounds: length 8–128, words 3–10, words overrides the
 * character sets, charset toggle must stay on outside words mode).
 */

import { buildGenRequest, normalizeMode, WORDS_MAX, WORDS_MIN } from './genMode.js';

const charOpts = {
    length: 20,
    words: 5,
    includeLowercase: true,
    includeUppercase: true,
    includeDigits: true,
    includeSymbols: false,
    pronounceable: false
};

describe('genMode', () => {
    it('normalizes unknown or missing modes to characters', () => {
        expect(normalizeMode('passphrase')).toBe('passphrase');
        expect(normalizeMode('characters')).toBe('characters');
        expect(normalizeMode('words')).toBe('characters');
        expect(normalizeMode(null)).toBe('characters');
        expect(normalizeMode(undefined)).toBe('characters');
    });

    it('characters mode keeps charset switches and drops words', () => {
        const req = buildGenRequest('characters', charOpts);
        expect(req.words).toBeUndefined();
        expect(req.length).toBe(20);
        expect(req.include_lowercase).toBe(true);
        expect(req.include_symbols).toBe(false);
        expect(req.pronounceable).toBe(false);
    });

    it('characters mode clamps length into the native 8–128 window', () => {
        expect(buildGenRequest('characters', { ...charOpts, length: 4 }).length).toBe(8);
        expect(buildGenRequest('characters', { ...charOpts, length: 500 }).length).toBe(128);
        // NaN/0 falls back to the native default 16
        expect(buildGenRequest('characters', { ...charOpts, length: Number.NaN }).length).toBe(16);
    });

    it('passphrase mode clamps words into 3–10 and forces pronounceable off', () => {
        const req = buildGenRequest('passphrase', charOpts);
        expect(req.words).toBe(5);
        expect(req.pronounceable).toBe(false);
        expect(buildGenRequest('passphrase', { ...charOpts, words: 1 }).words).toBe(WORDS_MIN);
        expect(buildGenRequest('passphrase', { ...charOpts, words: 99 }).words).toBe(WORDS_MAX);
        // fractional word counts floor before clamping
        expect(buildGenRequest('passphrase', { ...charOpts, words: 4.7 }).words).toBe(4);
        // pronounceable=true is meaningless with words override — dropped
        expect(buildGenRequest('passphrase', { ...charOpts, pronounceable: true }).pronounceable).toBe(false);
        expect(buildGenRequest('passphrase', { ...charOpts, words: Number.NaN }).words).toBe(WORDS_MIN);
    });
});
