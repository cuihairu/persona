// Vault list category filter: pure logic, no DOM. The kind string stored on
// each row (`data-kind`) mirrors SnapshotMeta.credential_type with the row
// builder's fallback (item.kind). Unknown kinds land in the login bucket,
// matching the row glyph's default.

export type KindFilter = 'all' | 'password' | 'totp' | 'bank_card';

export const KIND_FILTERS: readonly KindFilter[] = ['all', 'password', 'totp', 'bank_card'];

export function normalizeKind(raw: string | null | undefined): Exclude<KindFilter, 'all'> {
    const kind = (raw ?? '').toLowerCase();
    if (kind.includes('card')) return 'bank_card';
    if (kind.includes('totp') || kind.includes('otp')) return 'totp';
    return 'password';
}

export function matchesKind(rowKind: string | null | undefined, filter: KindFilter): boolean {
    return filter === 'all' || normalizeKind(rowKind) === filter;
}

export function countByKind(kinds: Array<string | null | undefined>): Record<KindFilter, number> {
    const counts: Record<KindFilter, number> = { all: kinds.length, password: 0, totp: 0, bank_card: 0 };
    for (const raw of kinds) {
        counts[normalizeKind(raw)] += 1;
    }
    return counts;
}

/** Combined visibility predicate: category filter AND free-text search (AND semantics). */
export function rowVisible(
    rowKind: string | null | undefined,
    rowText: string,
    filter: KindFilter,
    query: string
): boolean {
    const q = query.trim().toLowerCase();
    const textOk = !q || rowText.toLowerCase().includes(q);
    return matchesKind(rowKind, filter) && textOk;
}
