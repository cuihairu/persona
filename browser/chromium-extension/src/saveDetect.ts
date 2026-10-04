// Pure classification for the save/update bar (bridge protocol v4).
//
// The content script captures the fields of a submitted form and hands them
// here as plain data; everything testable lives in this module so the DOM
// wiring in content.ts stays thin. Heuristics mirror 1Password's bar:
// autocomplete attributes win, field count and naming break ties, and the
// final create-vs-update decision always rides the host's find_for_save
// answer plus an explicit user click — an imperfect scenario label only
// changes the default button, never what gets written.

export type SaveScenario = 'login' | 'new' | 'change';

export interface SaveScanInput {
    /** Lowercased `type` attribute ('password', 'text', 'email', ...). */
    inputType: string;
    autocomplete: string;
    name: string;
    id: string;
    placeholder: string;
    ariaLabel: string;
    value: string;
}

export interface SaveProposal {
    scenario: SaveScenario;
    username?: string;
    password: string;
    nameHint?: string;
}

const USERNAME_FIELD_HINTS = ['user', 'login', 'identifier', 'account', 'email', 'phone', 'mobile'];

function haystack(input: SaveScanInput): string {
    return [input.name, input.id, input.placeholder, input.ariaLabel]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
}

function looksLikeUsername(input: SaveScanInput): boolean {
    if (input.inputType === 'email') return true;
    if (input.inputType === 'password') return false;
    const text = haystack(input);
    return USERNAME_FIELD_HINTS.some((hint) => text.includes(hint));
}

/**
 * Classify the submitted form. Order matters:
 * - autocomplete attributes are the page's own statement and always win;
 * - a `current-password` field next to others means a change form;
 * - two+ password fields without one are password+confirm ⇒ registration.
 */
export function classifySaveScenario(inputs: SaveScanInput[]): SaveScenario {
    const passwords = inputs.filter((i) => i.inputType === 'password');
    if (passwords.length === 0) return 'login';

    const hasCurrent = passwords.some((p) => p.autocomplete === 'current-password');
    const hasNew = passwords.some((p) => p.autocomplete === 'new-password');

    if (passwords.length >= 2) {
        if (hasCurrent) return 'change';
        if (hasNew) return 'new';
        return 'new';
    }
    if (hasNew) return 'new';
    return 'login';
}

/**
 * Build the save proposal for a submitted form, or null when there is
 * nothing worth storing (no filled password field).
 *
 * Password pick: login/registration forms store the first filled password;
 * change forms order current → new → confirm, so the LAST filled field is
 * the new password (a current+confirm pair without autocomplete is still
 * classified 'change' only when one field says current-password, and the
 * last field is then the right one in both orderings).
 */
export function extractSaveProposal(
    inputs: SaveScanInput[],
    docTitle?: string,
    host?: string
): SaveProposal | null {
    const filled = inputs.filter((i) => i.inputType === 'password' && i.value);
    if (filled.length === 0) return null;

    const scenario = classifySaveScenario(inputs);
    const chosen = scenario === 'change' ? filled[filled.length - 1] : filled[0];

    const usernameInput = inputs.find((i) => looksLikeUsername(i) && i.value.trim());
    const nameHint = (docTitle ?? '').trim() || (host ?? '').trim() || undefined;

    return {
        scenario,
        username: usernameInput?.value.trim() || undefined,
        password: chosen.value,
        nameHint
    };
}
