/**
 * Autofill UX helpers (pure — unit-testable without DOM or chrome APIs).
 *
 * TOTP polish pieces: stale-code detection (a code about to roll over may
 * expire before the user submits), fill/copy notices carrying the remaining
 * window, and candidate disambiguation shared by the password/TOTP paths.
 */
/** A code with ≤ this many seconds left is treated as about to expire. */
export const TOTP_STALE_THRESHOLD_SECONDS = 3;
/** Wait out the rest of the window (plus 1s slack) before refetching a code. */
export function freshTotpWaitMs(remainingSeconds) {
    return (Math.max(0, remainingSeconds) + 1) * 1000;
}
/** True when the code may expire before submission — wait and refetch once. */
export function shouldWaitForFreshTotp(remainingSeconds) {
    return (typeof remainingSeconds === 'number' &&
        Number.isFinite(remainingSeconds) &&
        remainingSeconds >= 0 &&
        remainingSeconds <= TOTP_STALE_THRESHOLD_SECONDS);
}
export function totpFilledNotice(remainingSeconds) {
    if (typeof remainingSeconds === 'number' && remainingSeconds > 0) {
        return `2FA code filled (expires in ${remainingSeconds}s)`;
    }
    return '2FA code filled';
}
export function totpCopiedNotice(remainingSeconds, fallback = false) {
    const base = fallback ? '2FA code copied (fallback)' : '2FA code copied';
    if (typeof remainingSeconds === 'number' && remainingSeconds > 0) {
        return `${base} (expires in ${remainingSeconds}s)`;
    }
    return base;
}
/**
 * Pick the single auto-fill candidate for a mode: filter by type and minimum
 * match strength, prefer the per-origin remembered default, otherwise the
 * unique strongest match. Returns `ambiguous` so callers can surface a picker
 * instead of silently doing nothing when several candidates tie.
 */
export function pickSuggestion(items, mode, minStrength, defaultItemId) {
    const filtered = items
        .filter((s) => (s.credential_type ?? 'password') === mode)
        .filter((s) => (typeof s.match_strength === 'number' ? s.match_strength : 0) >= minStrength)
        .sort((a, b) => b.match_strength - a.match_strength);
    if (filtered.length === 0)
        return { picked: null, ambiguous: false };
    if (filtered.length === 1)
        return { picked: filtered[0], ambiguous: false };
    if (defaultItemId) {
        const wanted = filtered.find((s) => s.item_id === defaultItemId) ?? null;
        return { picked: wanted, ambiguous: wanted === null };
    }
    return { picked: null, ambiguous: true };
}
/**
 * Per-row meta line for the popup. Optional fields come from the bridge
 * (protocol v7+): `identity` labels which identity owns the entry, so users
 * can tell two same-host entries apart. Missing fields keep the old line.
 */
export function suggestionMetaLine(item) {
    const kind = (item.credential_type ?? 'password').toUpperCase().replace(/_/g, ' ');
    const parts = [`${kind} • match ${item.match_strength ?? '?'}`];
    if (item.username_hint)
        parts.push(item.username_hint);
    if (item.identity)
        parts.push(item.identity);
    return parts.join(' • ');
}
/** One-line context hint for the popup header; null when there is none. */
export function contextHintLine(ctx) {
    if (!ctx?.identity)
        return null;
    const score = typeof ctx.score === 'number' && Number.isFinite(ctx.score)
        ? ctx.score.toFixed(2)
        : '?';
    return `Context suggests ${ctx.identity} (score ${score})`;
}
//# sourceMappingURL=autofillUx.js.map