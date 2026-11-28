/**
 * Inline menu focus wiring: focusing a login/2FA field OFFERS the candidate
 * menu — it never fills by itself. While inlineMenuOnFocus is on, the silent
 * focus fill yields (gate in fill.ts, disabled switch in the popup); with
 * the menu off the old focus behavior applies unchanged.
 *
 * The shared opener also serves the inline-icon click path (icons.ts), so
 * both entry points pick and fill identically.
 */

import {
    candidateKindForField,
    classifyInlineMenuField,
    makeInlineMenuFieldKey,
    pickInlineMenuCandidates,
    shouldShowInlineMenu,
    type InlineCandidate,
    type InlineMenuCandidateKind
} from '../inlineMenu.js';
import { renderInlineMenu } from '../inlineMenuUi.js';
import { mountPersonaUi } from '../shadowUi.js';

import { state } from './state.js';
import { hideOverlay } from './overlay.js';
import { requestFill, requestTotp } from './fillRequests.js';
import { fetchSuggestions, isDomainAllowedForAutoFill, maybeRememberDefault } from './suggestions.js';

/**
 * Render the menu for an input with a prepared candidate list and wire the
 * pick actions (remember-default + fill/TOTP request). Single-overlay slot:
 * opening replaces whatever panel was up.
 */
export function openInlineMenu(
    input: HTMLInputElement,
    candidates: readonly InlineCandidate[]
): void {
    hideOverlay();

    const rect = input.getBoundingClientRect();
    const handle = renderInlineMenu(candidates, {
        field: {
            top: rect.top + window.scrollY,
            bottom: rect.bottom + window.scrollY,
            left: rect.left + window.scrollX,
            height: rect.height
        },
        mount: mountPersonaUi(document).root,
        fieldEl: input,
        onPick: (suggestion) => {
            if ((suggestion.credential_type ?? 'password') === 'totp') {
                void maybeRememberDefault('totp', suggestion.item_id);
                void requestTotp(suggestion.item_id, input);
            } else {
                void maybeRememberDefault('password', suggestion.item_id);
                void requestFill(suggestion.item_id, input);
            }
        }
    });
    state.autofillOverlay = handle.el;
    const previousClose = handle.close;
    handle.close = () => {
        previousClose();
        if (state.autofillOverlay === handle.el) state.autofillOverlay = null;
    };
}

/** Candidate strength floor for a menu kind (same defaults the fills use). */
function strengthFloorFor(kind: InlineMenuCandidateKind): number {
    return kind === 'totp'
        ? state.currentSettings.minMatchStrengthTotp
        : state.currentSettings.minMatchStrengthLogin;
}

/**
 * Focus-path verdict + open. Cheap synchronous gates run first (field kind,
 * setting, session repeat, debounce — the pure model with an optimistic
 * domain allowance); only when they pass do we pay the async domain gate and
 * a first-pool fetch, then re-run the pool gates with the real pool.
 */
export async function offerInlineMenuOnFocus(input: HTMLInputElement): Promise<void> {
    const kind = classifyInlineMenuField({
        inputType: input.type,
        name: input.name,
        id: input.id,
        autocomplete: input.getAttribute('autocomplete') || '',
        inputMode: input.inputMode || undefined,
        maxLength: input.maxLength >= 0 ? input.maxLength : null,
        ariaLabel: input.getAttribute('aria-label') || undefined
    });
    // identity fields need a surrounding form (same rule as the fill path's
    // identity fallback: a loose header search box never gets a menu)
    if (kind === 'identity' && !input.closest('form')) return;
    const fieldKey = makeInlineMenuFieldKey({
        formId: input.form?.id ?? null,
        name: input.name,
        id: input.id,
        inputType: input.type
    });
    const now = Date.now();
    const cheap = shouldShowInlineMenu({
        fieldKind: kind,
        inlineMenuOnFocus: state.currentSettings.inlineMenuOnFocus,
        domainAllowed: true,
        suggestionCount: 1,
        fieldKey,
        shownKeys: state.inlineMenuShownKeys,
        now,
        lastMenuAt: state.lastInlineMenuAt
    });
    if (!cheap.show) return;
    if (!kind) return; // unreachable after the gate; narrows for the compiler

    if (!(await isDomainAllowedForAutoFill())) return;
    if (state.currentSuggestions.length === 0) await fetchSuggestions();

    const menuKind = candidateKindForField(kind);
    const candidates = pickInlineMenuCandidates(
        state.currentSuggestions,
        menuKind,
        strengthFloorFor(menuKind)
    );
    if (candidates.length === 0) return; // empty pool: stay silent

    state.inlineMenuShownKeys.add(fieldKey);
    state.lastInlineMenuAt = now;
    openInlineMenu(input, candidates);
}
