import { observeForms, type DetectedForm, type DetectedField } from '../formScanner.js';
import { evaluateDomain, type DomainAssessment, type DomainPolicy } from '../domainPolicy.js';
import {
    DEFAULT_AUTOFILL_SETTINGS,
    getAutofillSettings,
    onAutofillSettingsChanged,
    type AutofillSettings
} from '../settings.js';
import {
    getAutofillDefaultsForOrigin,
    onAutofillDefaultsChanged,
    setAutofillDefaultsForOrigin,
    type OriginAutofillDefaults
} from '../autofillDefaults.js';
import {
    freshTotpWaitMs,
    pickSuggestion,
    shouldWaitForFreshTotp,
    totpCopiedNotice,
    totpFilledNotice
} from '../autofillUx.js';
import { extractSaveProposal, type SaveProposal, type SaveScanInput } from '../saveDetect.js';
import { planLoginStep } from '../loginSteps.js';
import { mountPersonaUi } from '../shadowUi.js';
import { isTrustedPasskeyOrigin } from '../passkeyOrigin.js';

import { state } from './state.js';
import type { SuggestionItem, FillCredential, CardFillData, PasskeyCandidate, PasskeyBridgeReply } from './types.js';
import { escapeHtml, fillInput, hasValue, IS_TOP_FRAME } from './util.js';
import { showNotification } from './overlay.js';
import { refreshOriginDefaults, isDomainAllowedForAutoFill, fetchSuggestions } from './suggestions.js';
import { requestFill, requestTotp } from './fillRequests.js';
import { isLikelyTotpInput, showInlineIcon, showGeneratorIcon, showSuggestionsDropdown } from './icons.js';
import { toggleOverlay, hideOverlay } from './overlay.js';


export function isFillableInput(input: HTMLInputElement): boolean {
    if (input.disabled || input.readOnly) return false;
    const style = window.getComputedStyle(input);
    if (style.display === 'none' || style.visibility === 'hidden') return false;
    if (input.getClientRects().length === 0) return false;
    return true;
}

/** 唯一命中/有默认则返回；多候选无默认返回 ambiguous，调用方弹选择器。 */
export function selectSuggestionWithDefault(
    mode: 'password' | 'totp',
    minStrength: number
): { picked: SuggestionItem | null; ambiguous: boolean } {
    const wantedId = mode === 'totp' ? state.currentOriginDefaults?.totpItemId : state.currentOriginDefaults?.passwordItemId;
    return pickSuggestion(state.currentSuggestions, mode, minStrength, wantedId);
}

export function normalizeUsername(value: string): string {
    return value.trim().toLowerCase();
}

export function doesUsernameMatchHint(typedUsername: string, hint: string): boolean {
    const typed = normalizeUsername(typedUsername);
    const candidate = normalizeUsername(hint);
    if (!typed || !candidate) return false;
    if (typed === candidate) return true;
    if (typed.includes(candidate) || candidate.includes(typed)) return true;
    return false;
}

export async function selectLoginSuggestion(minStrength: number, typedUsername?: string): Promise<SuggestionItem | null> {
    const filtered = state.currentSuggestions
        .filter((s) => (s.credential_type ?? 'password') === 'password')
        .filter((s) => (typeof s.match_strength === 'number' ? s.match_strength : 0) >= minStrength)
        .sort((a, b) => b.match_strength - a.match_strength);

    if (filtered.length === 0) return null;
    if (filtered.length === 1) return filtered[0];

    const typed = (typedUsername ?? '').trim();
    if (typed) {
        const matches = filtered.filter((s) => s.username_hint && doesUsernameMatchHint(typed, s.username_hint));
        if (matches.length === 1) return matches[0];
    }

    const wantedId = state.currentOriginDefaults?.passwordItemId;
    if (!wantedId) return null;
    return filtered.find((s) => s.item_id === wantedId) ?? null;
}

export function getBestLoginInputs(): { usernameInput?: HTMLInputElement; passwordInput?: HTMLInputElement } {
    for (const form of state.currentForms) {
        const passwordField = form.fields.find((f) => f.type === 'password');
        if (!passwordField?.selector) continue;
        const passwordEl = document.querySelector(passwordField.selector);
        if (!(passwordEl instanceof HTMLInputElement) || !isFillableInput(passwordEl)) continue;

        const usernameField = form.fields.find((f) => f.type === 'username' || f.type === 'email' || f.type === 'text');
        const usernameEl = usernameField?.selector ? document.querySelector(usernameField.selector) : null;
        const usernameInput =
            usernameEl instanceof HTMLInputElement && isFillableInput(usernameEl) ? usernameEl : undefined;

        return { usernameInput, passwordInput: passwordEl };
    }
    return {};
}

/**
 * Step 1 of a multi-step login: the page asks for a username only. Fill just
 * that field and remember the item as this origin's default so the password
 * page (a fresh document, a fresh content script) can finish the job with no
 * further interaction — see `loginSteps.ts` for when this is allowed at all.
 */
export async function fillUsernameStep(itemId: string, input: HTMLInputElement, userGesture: boolean) {
    const response = await chrome.runtime
        .sendMessage({
            type: 'persona_request_fill',
            origin: location.origin,
            itemId,
            userGesture
        })
        .catch(() => null);

    const username = response?.success ? (response.data?.username as string | undefined) : undefined;
    if (!username) {
        showNotification('Could not read the username from Persona', 'error');
        return false;
    }

    fillInput(input, username);
    showNotification('Username filled — continue to the next step', 'success');
    // The site accepted this identity; remember it as the origin default so
    // the password step can resolve the item without asking.
    await setAutofillDefaultsForOrigin(location.origin, { passwordItemId: itemId }).catch(() => null);
    void refreshOriginDefaults();
    return true;
}

/**
 * Identity field of a frame when no password field is present yet. Prefers
 * the form scanner's classification (which honours autocomplete), falls back
 * to the same name/id/placeholder hints the focus handler uses so SPA
 * username steps — which produce no scanned form — still resolve.
 */
export function findIdentityInput(focusedInput?: HTMLInputElement): HTMLInputElement | null {
    if (focusedInput instanceof HTMLInputElement && isFillableInput(focusedInput) &&
        focusedInput.type.toLowerCase() !== 'password') {
        const kind = classifyIdentityInput(focusedInput);
        if (kind !== 'none') return focusedInput;
    }

    for (const form of state.currentForms) {
        const field = form.fields.find((f) => f.type === 'username' || f.type === 'email');
        if (!field?.selector) continue;
        const el = document.querySelector(field.selector);
        if (el instanceof HTMLInputElement && isFillableInput(el)) return el;
    }

    // Last resort for forms the scanner never grouped (SPA step-1 forms are
    // invisible to it without a password/OTP seed). Restricted to inputs
    // inside a real <form>: a loose search/filter box in a page header has
    // no form around it and must never receive an identity.
    for (const el of document.querySelectorAll('input')) {
        if (!(el instanceof HTMLInputElement) || !isFillableInput(el)) continue;
        if (el.type.toLowerCase() === 'password') continue;
        if (!el.closest('form')) continue;
        if (classifyIdentityInput(el) === 'none') continue;
        return el;
    }
    return null;
}

export function classifyIdentityInput(input: HTMLInputElement): 'username' | 'email' | 'text' | 'none' {
    const type = input.type.toLowerCase();
    if (type === 'password' || type === 'number') return 'none';
    const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
    if (autocomplete === 'username' || autocomplete === 'email') {
        return autocomplete === 'email' ? 'email' : 'username';
    }
    if (type === 'email') return 'email';
    const haystack = [
        input.name,
        input.id,
        input.placeholder,
        input.getAttribute('aria-label')
    ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
    if (['user', 'login', 'identifier', 'account', 'email', 'mail'].some((hint) => haystack.includes(hint))) {
        return haystack.includes('mail') || haystack.includes('email') ? 'email' : 'username';
    }
    if (type === 'text' || type === 'search' || type === 'tel') return 'text';
    return 'none';
}

export async function maybeAutoFillLogin(trigger: 'load' | 'focus', focusedInput?: HTMLInputElement) {
    if (trigger === 'load' && !state.currentSettings.autoFillLoginOnLoad) return;
    if (trigger === 'focus' && !state.currentSettings.autoFillLoginOnFocus) return;

    const now = Date.now();
    if (now - state.lastLoginAutofillAttemptAt < 1500) return;

    if (!(await isDomainAllowedForAutoFill())) return;

    const { usernameInput, passwordInput } = getBestLoginInputs();
    const typedUsername = usernameInput?.value?.trim();
    const suggestion = await selectLoginSuggestion(state.currentSettings.minMatchStrengthLogin, typedUsername);
    if (!suggestion) return;

    if (passwordInput) {
        if (hasValue(passwordInput)) return;
        if (focusedInput && focusedInput.type === 'password' && focusedInput !== passwordInput) {
            return;
        }
        state.lastLoginAutofillAttemptAt = now;
        await requestFill(suggestion.item_id, usernameInput ?? passwordInput, trigger === 'focus');
        return;
    }

    // No password field in this frame/document: either step 1 of a multi-step
    // login, or nothing to do. `planLoginStep` owns that judgement.
    const identityInput = findIdentityInput(focusedInput);
    const action = planLoginStep({
        trigger,
        hasPasswordField: false,
        identityField: identityInput
            ? {
                kind: classifyIdentityInput(identityInput),
                autocomplete: (identityInput.getAttribute('autocomplete') || '').toLowerCase(),
                hasValue: hasValue(identityInput),
                isFocused: identityInput === focusedInput
            }
            : null,
        hasResolvableSuggestion: Boolean(suggestion)
    });
    if (action !== 'username') return;

    state.lastLoginAutofillAttemptAt = now;
    await fillUsernameStep(suggestion.item_id, identityInput!, trigger === 'focus');
}

export async function maybeAutoFillTotp(_trigger: 'focus', focusedInput?: HTMLInputElement) {
    if (!state.currentSettings.autoFillTotpOnFocus) return;

    const now = Date.now();
    if (now - state.lastTotpAutofillAttemptAt < 1500) return;

    if (!(await isDomainAllowedForAutoFill())) return;

    const { picked, ambiguous } = selectSuggestionWithDefault('totp', state.currentSettings.minMatchStrengthTotp);
    if (!picked) {
        // 多候选且无默认记忆：不再静默失败，就地弹出选择下拉
        if (ambiguous && focusedInput && !hasValue(focusedInput)) {
            state.lastTotpAutofillAttemptAt = now;
            showSuggestionsDropdown(focusedInput, 'totp');
        }
        return;
    }

    if (focusedInput && hasValue(focusedInput)) return;

    state.lastTotpAutofillAttemptAt = now;
    await requestTotp(picked.item_id, focusedInput, true);
}

// Handle keyboard shortcuts
export function handleKeydown(event: KeyboardEvent) {
    // Ctrl/Cmd + Shift + P to show Persona overlay (top frame only — see
    // IS_TOP_FRAME: key events inside a cross-origin iframe never reach the
    // parent document, and one overlay per frame would be noise).
    if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key === 'p' && IS_TOP_FRAME) {
        event.preventDefault();
        toggleOverlay();
    }

    // Escape to close overlay
    if (event.key === 'Escape' && state.autofillOverlay) {
        hideOverlay();
    }
}

/**
 * Focus path: make sure this frame has suggestions before planning a fill.
 * The load-time scan only asks the bridge for origins whose forms carry a
 * password/OTP field, so a username-only step would otherwise never see the
 * user's own accounts. Focus is user-initiated, so paying for one lookup
 * here is the right trade — and it stays bounded by fetchSuggestions' own
 * 1.5s throttle.
 */
export async function ensureSuggestionsThenAutofill(
    trigger: 'load' | 'focus',
    focusedInput?: HTMLInputElement
) {
    if (state.currentSuggestions.length === 0) {
        await fetchSuggestions();
    }
    await maybeAutoFillLogin(trigger, focusedInput);
}

// Handle focus on input fields
export function handleInputFocus(event: FocusEvent) {
    const target = event.target as HTMLElement;
    if (!(target instanceof HTMLInputElement)) return;

    // Check if this is a password or username field
    const fieldType = target.type.toLowerCase();
    const fieldName = (target.name || target.id || '').toLowerCase();
    const autocomplete = (target.getAttribute('autocomplete') || '').toLowerCase();

    const isPasswordField = fieldType === 'password';
    const isNewPasswordField = isPasswordField && autocomplete === 'new-password';
    const isUsernameField = fieldType === 'text' || fieldType === 'email' ||
        ['user', 'login', 'email', 'identifier'].some(hint => fieldName.includes(hint));
    const isTotpField = isLikelyTotpInput(target, fieldName);

    if (isPasswordField || isUsernameField) {
        if (state.currentSuggestions.some((s) => (s.credential_type ?? 'password') === 'password')) {
            showInlineIcon(target, 'password');
        }
        // A username-only step (multi-step login) has no password field, so
        // the load-time scan never fetched suggestions for this frame. A
        // focus is a real user action: fetch once, then let the planner decide.
        void ensureSuggestionsThenAutofill('focus', target);
    }
    // Show password generator icon on registration forms (new-password field)
    if (isNewPasswordField && state.currentSettings.savePromptEnabled) {
        showGeneratorIcon(target);
    }
    if (isTotpField && state.currentSuggestions.some((s) => (s.credential_type ?? 'password') === 'totp')) {
        showInlineIcon(target, 'totp');
        void maybeAutoFillTotp('focus', target);
    }
}

