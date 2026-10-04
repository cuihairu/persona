// Cross-navigation hand-off for the save/update bar (bridge protocol v4).
//
// Most real logins navigate: the page that captured the password is gone by
// the time the user lands back on the site, so an in-page bar alone would
// only ever work for SPAs. The background service worker therefore keeps one
// pending proposal in `chrome.storage.session` — memory-backed, never written
// to disk, cleared by the browser when the extension shuts down — and the
// next page load of the *same origin* picks it up and shows the bar again.
//
// The stash carries the plaintext password on purpose (it is what the user
// just typed); it is strictly origin-bound, time-limited, and it is dropped
// as soon as the user acts on it or the bar is dismissed.

import type { SaveProposal } from './saveDetect';

export interface PendingSaveEntry extends SaveProposal {
    /** Exact page origin that captured the form. Never matched loosely. */
    origin: string;
    at: number;
}

export const PENDING_SAVE_KEY = 'persona_pending_save_v1';
/** Long enough to survive a redirect + MFA hop, short enough that a
 *  forgotten bar cannot resurface a password hours later. */
export const PENDING_SAVE_TTL_MS = 2 * 60 * 1000;

function normalizeOrigin(origin: string | undefined | null): string {
    return (origin ?? '').trim();
}

/**
 * A stashed proposal may only be restored when it is aimed at exactly this
 * origin, still inside the TTL, and actually carries a password. Anything
 * else is treated as absent (and should be dropped).
 */
export function isPendingSaveUsable(
    entry: PendingSaveEntry | null | undefined,
    origin: string,
    now: number = Date.now()
): entry is PendingSaveEntry {
    if (!entry) return false;
    if (typeof entry.origin !== 'string') return false;
    if (normalizeOrigin(entry.origin) !== normalizeOrigin(origin)) return false;
    if (typeof entry.password !== 'string' || !entry.password) return false;
    if (typeof entry.at !== 'number' || !Number.isFinite(entry.at)) return false;
    if (now - entry.at > PENDING_SAVE_TTL_MS) return false;
    return true;
}

export async function stashPendingSave(
    entry: PendingSaveEntry,
    now: number = Date.now()
): Promise<{ duplicate: boolean }> {
    const candidate = { ...entry, at: entry.at || now };
    const existing = (await chrome.storage.session.get(PENDING_SAVE_KEY))?.[
        PENDING_SAVE_KEY
    ] as PendingSaveEntry | undefined;

    // Cross-frame dedup: one login submit can be seen by several frames of
    // the same origin (nested same-origin iframes, plus the click+submit pair
    // on the same page). Whoever renders first owns the slot; the others are
    // told it is a duplicate so they don't stack a second bar on screen.
    if (
        isPendingSaveUsable(existing, candidate.origin, candidate.at) &&
        isSameProposal(existing!, candidate)
    ) {
        return { duplicate: true };
    }

    await chrome.storage.session.set({ [PENDING_SAVE_KEY]: candidate });
    return { duplicate: false };
}

/** Same site + same account + same password ⇒ the same save, already shown. */
export function isSameProposal(a: PendingSaveEntry, b: PendingSaveEntry): boolean {
    return (
        normalizeOrigin(a.origin) === normalizeOrigin(b.origin) &&
        (a.username ?? '').trim() === (b.username ?? '').trim() &&
        a.password === b.password
    );
}

/**
 * Read-and-clear: exactly one page load can restore a given proposal, so a
 * reload cannot stack bars. Expired / foreign entries are cleared on the way
 * out instead of lingering in session storage.
 */
export async function takePendingSave(
    origin: string,
    now: number = Date.now()
): Promise<PendingSaveEntry | null> {
    const stored = await chrome.storage.session.get(PENDING_SAVE_KEY);
    const entry = stored?.[PENDING_SAVE_KEY] as PendingSaveEntry | undefined;
    if (!entry) return null;
    if (!isPendingSaveUsable(entry, origin, now)) {
        await chrome.storage.session.remove(PENDING_SAVE_KEY);
        return null;
    }
    await chrome.storage.session.remove(PENDING_SAVE_KEY);
    return entry;
}

export async function clearPendingSave(): Promise<void> {
    await chrome.storage.session.remove(PENDING_SAVE_KEY);
}