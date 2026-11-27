import {
    KIND_FILTERS,
    countByFacts,
    matchesFilter,
    normalizeKind,
    rowVisible,
    type RowFacts
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

describe('matchesFilter', () => {
    const rows: RowFacts[] = [
        { kind: 'password' },
        { kind: 'totp' },
        { kind: 'bank_card' },
        { kind: 'weird' },
        { kind: 'totp', favorite: true }
    ];

    it('keeps everything under the all filter', () => {
        expect(rows.filter((r) => matchesFilter(r, 'all'))).toHaveLength(5);
    });

    it('selects one kind bucket per concrete filter', () => {
        expect(rows.filter((r) => matchesFilter(r, 'password'))).toEqual([{ kind: 'password' }, { kind: 'weird' }]);
        expect(rows.filter((r) => matchesFilter(r, 'totp'))).toEqual([{ kind: 'totp' }, { kind: 'totp', favorite: true }]);
        expect(rows.filter((r) => matchesFilter(r, 'bank_card'))).toEqual([{ kind: 'bank_card' }]);
    });

    it('selects only favorites regardless of kind', () => {
        expect(rows.filter((r) => matchesFilter(r, 'favorite'))).toEqual([{ kind: 'totp', favorite: true }]);
    });

    it('treats missing favorite flag as not favorite', () => {
        expect(matchesFilter({ kind: 'password', favorite: false }, 'favorite')).toBe(false);
        expect(matchesFilter({}, 'favorite')).toBe(false);
    });
});

describe('countByFacts', () => {
    it('counts each bucket plus favorites with the all total', () => {
        expect(countByFacts([
            { kind: 'password', favorite: true },
            { kind: 'totp' },
            { kind: 'totp', favorite: true },
            { kind: 'bank_card' }
        ])).toEqual({ all: 4, favorite: 2, password: 1, totp: 2, bank_card: 1 });
    });

    it('returns zeros for an empty list', () => {
        expect(countByFacts([])).toEqual({ all: 0, favorite: 0, password: 0, totp: 0, bank_card: 0 });
    });
});

describe('rowVisible', () => {
    it('combines category and text with AND semantics', () => {
        expect(rowVisible({ kind: 'totp' }, 'GitHub auth', 'totp', 'git')).toBe(true);
        expect(rowVisible({ kind: 'totp' }, 'GitHub auth', 'password', 'git')).toBe(false);
        expect(rowVisible({ kind: 'totp' }, 'GitHub auth', 'all', 'nomatch')).toBe(false);
    });

    it('layers the favorite filter over text search', () => {
        expect(rowVisible({ kind: 'totp', favorite: true }, 'GitHub', 'favorite', '')).toBe(true);
        expect(rowVisible({ kind: 'totp', favorite: true }, 'GitHub', 'favorite', 'mail')).toBe(false);
        expect(rowVisible({ kind: 'password' }, 'GitHub', 'favorite', '')).toBe(false);
    });

    it('matches text case-insensitively and trims the query', () => {
        expect(rowVisible({ kind: 'password' }, 'GitHub', 'all', '  GIT ')).toBe(true);
    });

    it('treats an empty query as pass-through for the text half', () => {
        expect(rowVisible({ kind: 'bank_card' }, '', 'bank_card', '')).toBe(true);
    });
});

describe('KIND_FILTERS', () => {
    it('lists the five shipped filters in display order', () => {
        expect(KIND_FILTERS).toEqual(['all', 'favorite', 'password', 'totp', 'bank_card']);
    });
});
