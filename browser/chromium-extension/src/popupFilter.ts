// Vault list category filter: pure logic, no DOM. The kind string stored on
// each row (`data-kind`) mirrors SnapshotMeta.credential_type with the row
// builder's fallback (item.kind). Unknown kinds land in the login bucket,
// matching the row glyph's default. The favorites filter reads a separate
// `favorite` fact (SnapshotMeta.is_favorite) — suggestions carry no such
// field, so favorite display is vault-list only.

export type KindFilter = 'all' | 'favorite' | 'password' | 'totp' | 'bank_card';

export const KIND_FILTERS: readonly KindFilter[] = ['all', 'favorite', 'password', 'totp', 'bank_card'];

export interface RowFacts {
    kind?: string | null;
    favorite?: boolean;
}

export function normalizeKind(raw: string | null | undefined): 'password' | 'totp' | 'bank_card' {
    const kind = (raw ?? '').toLowerCase();
    if (kind.includes('card')) return 'bank_card';
    if (kind.includes('totp') || kind.includes('otp')) return 'totp';
    return 'password';
}

export function matchesFilter(facts: RowFacts, filter: KindFilter): boolean {
    if (filter === 'all') return true;
    if (filter === 'favorite') return facts.favorite === true;
    return normalizeKind(facts.kind) === filter;
}

export function countByFacts(rows: RowFacts[]): Record<KindFilter, number> {
    const counts: Record<KindFilter, number> = { all: rows.length, favorite: 0, password: 0, totp: 0, bank_card: 0 };
    for (const facts of rows) {
        if (facts.favorite === true) counts.favorite += 1;
        counts[normalizeKind(facts.kind)] += 1;
    }
    return counts;
}

/** Combined visibility predicate: category filter AND free-text search (AND semantics). */
export function rowVisible(
    facts: RowFacts,
    rowText: string,
    filter: KindFilter,
    query: string
): boolean {
    const q = query.trim().toLowerCase();
    const textOk = !q || rowText.toLowerCase().includes(q);
    return matchesFilter(facts, filter) && textOk;
}
