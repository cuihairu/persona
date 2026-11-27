/**
 * Popup keyboard navigation: type-to-search, arrow keys walk the merged item
 * lists, Enter activates, Esc backs out. Pure logic here — DOM wiring lives
 * in popup.ts.
 */

export interface NavRow {
    /** stable identity: data-item-id or a generated row key */
    key: string;
    visible: boolean;
    /** true when the row's primary action is a fill (suggestion rows) */
    isFill: boolean;
}

/** Rows in visual order (suggestions block first, then vault), visible only.
 * Generic so callers carrying extra per-row state (e.g. the DOM element) keep it. */
export function activatableRows<T extends NavRow>(rows: T[]): T[] {
    return rows.filter((row) => row.visible);
}

/**
 * Index step within the activatable list. `delta` is +1 (ArrowDown) or -1
 * (ArrowUp); selection wraps at both ends, and -1 (nothing selected yet)
 * starts from the top on ArrowDown / the bottom on ArrowUp.
 */
export function steppedIndex(count: number, current: number, delta: number): number {
    if (count <= 0) return -1;
    if (current < 0 || current >= count) return delta > 0 ? 0 : count - 1;
    return (current + delta + count) % count;
}

/** True when the key should be swallowed by the navigator (no default scroll). */
export function isNavKey(key: string): boolean {
    return key === 'ArrowDown' || key === 'ArrowUp' || key === 'Enter' || key === 'Escape';
}
