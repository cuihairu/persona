/**
 * Inline menu trigger and candidate model (1Password-style): focusing a
 * login/2FA field offers a clickable candidate menu — it NEVER fills by
 * itself. Silent fill stays on its own switches (and yields when the menu
 * is on, see the popup wiring); this module only decides whether a focus
 * deserves a menu and which candidates to list.
 *
 * Pure logic — DOM/event wiring lives in fill.ts/icons.ts (inline menu row
 * 021/022). Import from the content layer only: the background must not
 * reach into content modules (dist/content is a build-cleanup casualty).
 */

export type InlineMenuFieldKind = 'password' | 'totp' | 'identity';
export type InlineMenuCandidateKind = 'password' | 'totp';

export interface InlineFieldParts {
    inputType: string;
    name: string;
    id: string;
    autocomplete: string;
    inputMode?: string;
    maxLength?: number | null;
    ariaLabel?: string;
}

const TOTP_NAME_HINTS = ['otp', 'totp', '2fa', 'twofactor', 'verification', 'token', 'mfa'];
const IDENTITY_NAME_HINTS = ['user', 'login', 'email', 'identifier'];

/**
 * Classify a focused input the same way the focus handler does (fill.ts
 * heuristics, mirrored here so tests can pin the contract). Identity fields
 * (username/email) show login candidates; password fields show login
 * candidates too; totp fields show one-time-code candidates.
 */
export function classifyInlineMenuField(parts: InlineFieldParts): InlineMenuFieldKind | null {
    const type = (parts.inputType || '').toLowerCase();
    if (type === 'password') return 'password';

    const name = `${parts.name || ''} ${parts.id || ''}`.toLowerCase();
    const autocomplete = (parts.autocomplete || '').toLowerCase();

    if (autocomplete === 'one-time-code') return 'totp';
    if (TOTP_NAME_HINTS.some((hint) => name.includes(hint))) return 'totp';
    const inputMode = (parts.inputMode || '').toLowerCase();
    if (inputMode === 'numeric') {
        const maxLen = parts.maxLength ?? -1;
        if ((maxLen >= 4 && maxLen <= 10) || maxLen === 1) return 'totp';
    }
    const aria = (parts.ariaLabel || '').toLowerCase();
    if (aria.includes('verification') || aria.includes('authenticator') || aria.includes('code') || aria.includes('digit')) {
        return 'totp';
    }

    if (type === 'text' || type === 'email') return 'identity';
    if (IDENTITY_NAME_HINTS.some((hint) => name.includes(hint))) return 'identity';
    return null;
}

/** Candidate pool kind a field kind offers (identity fields offer logins). */
export function candidateKindForField(kind: InlineMenuFieldKind): InlineMenuCandidateKind {
    return kind === 'totp' ? 'totp' : 'password';
}

/**
 * Stable per-session key of a field so the same input is not re-offered.
 * Derived from structural attributes only (no DOM nodes → pure).
 */
export function makeInlineMenuFieldKey(parts: {
    formId?: string | null;
    name: string;
    id: string;
    inputType: string;
}): string {
    return `${parts.formId ?? ''}|${parts.name || parts.id || ''}|${parts.inputType}`;
}

export type InlineMenuVerdictReason =
    | 'ok'
    | 'not-menu-field'
    | 'setting-off'
    | 'domain-blocked'
    | 'empty-pool'
    | 'repeat'
    | 'debounced';

export interface InlineMenuTriggerInput {
    fieldKind: InlineMenuFieldKind | null;
    /** the inlineMenuOnFocus setting (wired in the settings row) */
    inlineMenuOnFocus: boolean;
    /** result of the same domain policy gate the fills use */
    domainAllowed: boolean;
    /** candidate pool size for this field's kind */
    suggestionCount: number;
    fieldKey: string;
    /** keys already offered this session (same field never re-offers) */
    shownKeys: ReadonlySet<string>;
    now: number;
    lastMenuAt: number;
    debounceMs?: number;
}

export interface InlineMenuVerdict {
    show: boolean;
    reason: InlineMenuVerdictReason;
}

/**
 * Decide whether a focus should open the inline menu. Order mirrors the
 * cheap-to-expensive gates: field kind → setting → domain policy → pool →
 * session repeat → debounce.
 */
export function shouldShowInlineMenu(input: InlineMenuTriggerInput): InlineMenuVerdict {
    if (!input.fieldKind) return { show: false, reason: 'not-menu-field' };
    if (!input.inlineMenuOnFocus) return { show: false, reason: 'setting-off' };
    if (!input.domainAllowed) return { show: false, reason: 'domain-blocked' };
    if (input.suggestionCount <= 0) return { show: false, reason: 'empty-pool' };
    if (input.shownKeys.has(input.fieldKey)) return { show: false, reason: 'repeat' };
    const debounceMs = input.debounceMs ?? 800;
    if (input.now - input.lastMenuAt < debounceMs) return { show: false, reason: 'debounced' };
    return { show: true, reason: 'ok' };
}

export interface InlineCandidate {
    item_id: string;
    title: string;
    username_hint?: string;
    match_strength: number;
    credential_type?: string;
}

/**
 * The menu's candidate list from the shared get_suggestions pool: same kind
 * only, strength floor applied (missing strength counts as 0), strongest
 * first, hard-capped so a big vault cannot blow the menu height.
 */
export function pickInlineMenuCandidates(
    suggestions: readonly InlineCandidate[],
    kind: InlineMenuCandidateKind,
    minStrength: number,
    cap = 8
): InlineCandidate[] {
    return suggestions
        .filter((s) => (s.credential_type ?? 'password') === kind)
        .filter((s) => (typeof s.match_strength === 'number' ? s.match_strength : 0) >= minStrength)
        .sort((a, b) => b.match_strength - a.match_strength)
        .slice(0, Math.max(1, cap));
}
