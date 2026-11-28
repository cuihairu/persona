/**
 * Incognito policy: a private window must never leak browsing intent into
 * the profile — the save bar (and its background stash) is the one surface
 * that would persist what the user typed, so it is suppressed entirely.
 * Fills stay available (they write to the page only). Pure predicates —
 * DOM/messaging wiring lives in saveBar.ts and the background relay.
 */

export interface IncognitoSenderLike {
    tab?: { incognito?: boolean };
}

/**
 * Narrow a messaging sender to its tab's incognito flag. Anything without
 * a definitive `true` is treated as a normal context (extension pages,
 * tabs without the flag, probe calls from tests).
 */
export function isIncognitoSender(sender: IncognitoSenderLike | null | undefined): boolean {
    return sender?.tab?.incognito === true;
}

export interface SaveBarGateInput {
    isIncognito: boolean;
    savePromptEnabled: boolean;
    savePromptDisabled?: boolean;
}

/**
 * Single save-bar policy gate: incognito wins over everything (no save
 * offers in private windows), then the global setting, then the per-origin
 * "never" choice from a previous bar interaction.
 */
export function shouldSuppressSaveBar(input: SaveBarGateInput): boolean {
    if (input.isIncognito) return true;
    if (!input.savePromptEnabled) return true;
    if (input.savePromptDisabled) return true;
    return false;
}
