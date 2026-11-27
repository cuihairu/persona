import { activatableRows, steppedIndex, isNavKey, type NavRow } from './popupNav.js';

describe('popupNav activatableRows', () => {
    it('keeps only visible rows in order', () => {
        const rows: NavRow[] = [
            { key: 'a', visible: true, isFill: true },
            { key: 'b', visible: false, isFill: false },
            { key: 'c', visible: true, isFill: false }
        ];
        expect(activatableRows(rows).map((r) => r.key)).toEqual(['a', 'c']);
    });

    it('returns empty for all-hidden input', () => {
        expect(activatableRows([{ key: 'x', visible: false, isFill: true }])).toEqual([]);
    });
});

describe('popupNav steppedIndex', () => {
    it('returns -1 for an empty list', () => {
        expect(steppedIndex(0, -1, 1)).toBe(-1);
        expect(steppedIndex(0, 3, -1)).toBe(-1);
    });

    it('starts from the top on ArrowDown when nothing is selected', () => {
        expect(steppedIndex(5, -1, 1)).toBe(0);
    });

    it('starts from the bottom on ArrowUp when nothing is selected', () => {
        expect(steppedIndex(5, -1, -1)).toBe(4);
    });

    it('steps down and up within bounds', () => {
        expect(steppedIndex(5, 0, 1)).toBe(1);
        expect(steppedIndex(5, 2, 1)).toBe(3);
        expect(steppedIndex(5, 3, -1)).toBe(2);
    });

    it('wraps at both ends', () => {
        expect(steppedIndex(5, 4, 1)).toBe(0);
        expect(steppedIndex(5, 0, -1)).toBe(4);
    });

    it('recovers from an out-of-range current index', () => {
        expect(steppedIndex(3, 99, 1)).toBe(0);
        expect(steppedIndex(3, 99, -1)).toBe(2);
    });

    it('handles a single row', () => {
        expect(steppedIndex(1, -1, 1)).toBe(0);
        expect(steppedIndex(1, 0, 1)).toBe(0);
        expect(steppedIndex(1, 0, -1)).toBe(0);
    });
});

describe('popupNav isNavKey', () => {
    it('accepts the four navigation keys', () => {
        expect(isNavKey('ArrowDown')).toBe(true);
        expect(isNavKey('ArrowUp')).toBe(true);
        expect(isNavKey('Enter')).toBe(true);
        expect(isNavKey('Escape')).toBe(true);
    });

    it('rejects typing and modifier keys', () => {
        expect(isNavKey('a')).toBe(false);
        expect(isNavKey('Shift')).toBe(false);
        expect(isNavKey('/')).toBe(false);
    });
});
