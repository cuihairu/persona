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
//# sourceMappingURL=autofillUx.js.map