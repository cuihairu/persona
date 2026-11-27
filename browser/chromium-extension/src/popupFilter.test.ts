import {
    KIND_FILTERS,
    countByKind,
    matchesKind,
    normalizeKind,
    rowVisible
} from './popupFilter.js';

describe('normalizeKind', () => {
    it('maps known credential types', () => {
        expect(normalizeKind('password')).toBe('password');
        expect(normalizeKind('totp')).toBe('totp');
        expect(normalizeKind('bank_card')).toBe('bank_card');
    });

    it('is case-insensitive and tolerant of variants', () => {
        expect(normalizeKind('BANK_CARD')).toBe('bank_card');
        expect(normalizeKind('HotpToken')).toBe('totp');
        expect(normalizeKind('CreditCard')).toBe('bank_card');
    });

    it('falls back to the login bucket for unknown or empty kinds', () => {
        expect(normalizeKind('credential')).toBe('password');
        expect(normalizeKind('')).toBe('password');
        expect(normalizeKind(null)).toBe('password');
        expect(normalizeKind(undefined)).toBe('password');
    });
});

describe('matchesKind', () => {
    const kinds = ['password', 'totp', 'bank_card', 'weird'];

    it('keeps everything under the all filter', () => {
        expect(kinds.filter((k) => matchesKind(k, 'all'))).toEqual(kinds);
    });

    it('selects exactly one bucket per concrete filter', () => {
        expect(kinds.filter((k) => matchesKind(k, 'password'))).toEqual(['password', 'weird']);
        expect(kinds.filter((k) => matchesKind(k, 'totp'))).toEqual(['totp']);
        expect(kinds.filter((k) => matchesKind(k, 'bank_card'))).toEqual(['bank_card']);
    });
});

describe('countByKind', () => {
    it('counts each bucket with the all total', () => {
        expect(countByKind(['password', 'totp', 'totp', 'bank_card'])).toEqual({
            all: 4,
            password: 1,
            totp: 2,
            bank_card: 1
        });
    });

    it('returns zeros for an empty list', () => {
        expect(countByKind([])).toEqual({ all: 0, password: 0, totp: 0, bank_card: 0 });
    });
});

describe('rowVisible', () => {
    it('combines category and text with AND semantics', () => {
        expect(rowVisible('totp', 'GitHub auth', 'totp', 'git')).toBe(true);
        expect(rowVisible('totp', 'GitHub auth', 'password', 'git')).toBe(false);
        expect(rowVisible('totp', 'GitHub auth', 'all', 'nomatch')).toBe(false);
    });

    it('matches text case-insensitively and trims the query', () => {
        expect(rowVisible('password', 'GitHub', 'all', '  GIT ')).toBe(true);
    });

    it('treats an empty query as pass-through for the text half', () => {
        expect(rowVisible('bank_card', '', 'bank_card', '')).toBe(true);
    });
});

describe('KIND_FILTERS', () => {
    it('lists the four shipped filters in display order', () => {
        expect(KIND_FILTERS).toEqual(['all', 'password', 'totp', 'bank_card']);
    });
});
