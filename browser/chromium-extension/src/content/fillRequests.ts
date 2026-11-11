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
import { sleep, hasValue, fillInput } from './util.js';
import { showNotification } from './overlay.js';
import { isDomainAllowedForAutoFill } from './suggestions.js';
import { selectSuggestionWithDefault } from './fill.js';


export async function requestFill(itemId: string, targetInput?: HTMLInputElement, userGesture = true) {
    try {
        const response = await chrome.runtime.sendMessage({
            type: 'persona_request_fill',
            origin: location.origin,
            itemId,
            userGesture
        });

        if (response?.success && response.data) {
            fillCredential(response.data, targetInput);
        } else {
            console.error('[Persona] Fill failed:', response?.error);
            if (String(response?.error || '').startsWith('user_confirmation_required')) {
                showNotification('Needs confirmation: open Persona popup and trust this domain', 'error');
                return;
            }
            showNotification('Failed to fill: ' + (response?.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('[Persona] Fill request error:', error);
    }
}

export function sendTotpRequest(itemId: string, userGesture: boolean) {
    return chrome.runtime.sendMessage({
        type: 'persona_get_totp',
        origin: location.origin,
        itemId,
        userGesture
    });
}

export async function requestTotp(itemId: string, targetInput?: HTMLInputElement, userGesture = true) {
    try {
        let response = await sendTotpRequest(itemId, userGesture);

        // 临期码（剩余 ≤3s）可能在用户提交前过期：等过周期边界再取一次新码。
        // 重取仍属同一次用户动作，userGesture 照传（桥侧手势闸门语义不变）。
        if (
            response?.success &&
            response.data?.code &&
            shouldWaitForFreshTotp(response.data.remaining_seconds)
        ) {
            await sleep(freshTotpWaitMs(response.data.remaining_seconds));
            response = await sendTotpRequest(itemId, true);
        }

        if (response?.success && response.data?.code) {
            const code = String(response.data.code);
            const remaining = response.data.remaining_seconds as number | undefined;
            const input = targetInput ?? findTotpInput();
            if (input) {
                fillTotpCode(input, code);
                showNotification(totpFilledNotice(remaining), 'success');
            } else {
                const copied = await chrome.runtime
                    .sendMessage({
                        type: 'persona_copy',
                        origin: location.origin,
                        itemId,
                        field: 'totp',
                        userGesture: true
                    })
                    .then((r) => Boolean(r?.success && r?.data?.copied))
                    .catch(() => false);

                if (copied) {
                    showNotification(totpCopiedNotice(remaining), 'success');
                } else {
                    await copyToClipboard(code);
                    showNotification(totpCopiedNotice(remaining, true), 'success');
                }
            }
        } else {
            console.error('[Persona] TOTP failed:', response?.error);
            if (String(response?.error || '').startsWith('user_confirmation_required')) {
                showNotification('Needs confirmation: open Persona popup and trust this domain', 'error');
                return;
            }
            showNotification('Failed to get 2FA code: ' + (response?.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('[Persona] TOTP request error:', error);
        showNotification('Failed to get 2FA code', 'error');
    }
}

export function findTotpInput(): HTMLInputElement | null {
    const form = state.currentForms[0];
    const totpField = form?.fields?.find((f) => f.type === 'totp');
    if (totpField?.selector) {
        const el = document.querySelector(totpField.selector);
        if (el instanceof HTMLInputElement) return el;
    }

    const fallback = document.querySelector('input[autocomplete="one-time-code"]');
    return fallback instanceof HTMLInputElement ? fallback : null;
}

export function isOtpDigitInput(input: HTMLInputElement): boolean {
    if (input.disabled || input.readOnly) return false;
    const type = input.type.toLowerCase();
    if (!['text', 'tel', 'number'].includes(type)) return false;
    const maxLen = input.maxLength;
    if (maxLen === 1) return true;
    const inputMode = (input.inputMode || '').toLowerCase();
    if (inputMode === 'numeric' && maxLen === 0) {
        const aria = (input.getAttribute('aria-label') || '').toLowerCase();
        if (aria.includes('digit')) return true;
    }
    return false;
}

export function findOtpGroupInputs(target: HTMLInputElement): HTMLInputElement[] {
    const ancestors: Element[] = [];
    let node: Element | null = target;
    for (let i = 0; i < 4 && node; i++) {
        ancestors.push(node);
        node = node.parentElement;
    }

    for (const container of ancestors) {
        const inputs = Array.from(container.querySelectorAll('input'))
            .filter((el): el is HTMLInputElement => el instanceof HTMLInputElement)
            .filter(isOtpDigitInput);
        if (inputs.length >= 4 && inputs.length <= 10 && inputs.includes(target)) {
            return inputs;
        }
    }

    const formRoot = target.form ?? target.closest('form');
    if (formRoot) {
        const inputs = Array.from(formRoot.querySelectorAll('input'))
            .filter((el): el is HTMLInputElement => el instanceof HTMLInputElement)
            .filter(isOtpDigitInput);
        if (inputs.length >= 4 && inputs.length <= 10 && inputs.includes(target)) {
            return inputs;
        }
    }

    return [];
}

export function fillTotpCode(target: HTMLInputElement, code: string) {
    const group = findOtpGroupInputs(target);
    if (group.length >= 4) {
        const digits = code.split('');
        for (let i = 0; i < group.length && i < digits.length; i++) {
            if (hasValue(group[i])) continue;
            fillInput(group[i], digits[i]);
        }
        return;
    }

    if (hasValue(target)) return;
    fillInput(target, code);
}

export function selectFormForTarget(targetInput?: HTMLInputElement): DetectedForm | null {
    if (!state.currentForms.length) return null;
    if (!targetInput) return state.currentForms[0];

    for (const form of state.currentForms) {
        for (const field of form.fields) {
            if (!field.selector) continue;
            try {
                const el = document.querySelector(field.selector);
                if (el === targetInput) return form;
            } catch {
                // ignore
            }
        }
    }

    const targetForm = targetInput.form ?? targetInput.closest('form');
    if (targetForm) {
        for (const form of state.currentForms) {
            for (const field of form.fields) {
                if (!field.selector) continue;
                try {
                    const el = document.querySelector(field.selector);
                    if (el instanceof HTMLElement && el.closest('form') === targetForm) return form;
                } catch {
                    // ignore
                }
            }
        }
    }

    return state.currentForms[0];
}

// Fill credential into form
export function fillCredential(credential: FillCredential, targetInput?: HTMLInputElement) {
    if (credential.card) {
        fillCard(credential.card);
        return;
    }

    const form = selectFormForTarget(targetInput);
    if (!form) {
        console.warn('[Persona] No form detected');
        return;
    }

    // Find username field
    const usernameField = form.fields.find(f =>
        f.type === 'username' || f.type === 'email' || f.type === 'text'
    );

    // Find password field
    const passwordField = form.fields.find(f => f.type === 'password');

    // Fill username
    if (credential.username && usernameField) {
        const input = document.querySelector(usernameField.selector) as HTMLInputElement;
        if (input) {
            if (!hasValue(input)) fillInput(input, credential.username);
        }
    }

    // Fill password
    if (credential.password && passwordField) {
        const input = document.querySelector(passwordField.selector) as HTMLInputElement;
        if (input) {
            if (!hasValue(input)) fillInput(input, credential.password);
        }
    }

    showNotification('Credentials filled successfully!', 'success');
    void maybeChainFillTotp();
}

/** Count payment-card fields in a detected form (used to pick the checkout form). */
export function cardFieldCount(form: DetectedForm): number {
    return form.fields.filter((field) => field.type.startsWith('card_')).length;
}

/**
 * Fill card fields on the page. CVV is deliberately not auto-filled: the
 * bridge never returns it, and injecting it into page DOM would expose it to
 * page scripts — CVV stays a copy-only value end to end.
 */
export function fillCard(card: CardFillData) {
    if (!state.currentForms.length) {
        console.warn('[Persona] No form detected');
        showNotification('No form detected on this page', 'error');
        return;
    }

    // Checkout pages can also host login forms: target the form with the
    // most card fields.
    const form = [...state.currentForms]
        .sort((a, b) => cardFieldCount(b) - cardFieldCount(a))
        .find((candidate) => cardFieldCount(candidate) > 0);
    if (!form) {
        console.warn('[Persona] No card form detected');
        showNotification('No card form detected on this page', 'error');
        return;
    }

    // Mapping of bridge card payload keys → scanned field kinds. cvv has no
    // entry on purpose (see above).
    const mapping: Array<[keyof CardFillData, string]> = [
        ['card_number', 'card_number'],
        ['cardholder_name', 'card_name'],
        ['expiry_date', 'card_expiry']
    ];

    let filled = 0;
    for (const [dataKey, fieldKind] of mapping) {
        const value = card[dataKey];
        if (!value) continue;
        const field = form.fields.find((candidate) => candidate.type === fieldKind);
        if (!field) continue;
        const input = document.querySelector(field.selector) as HTMLInputElement | null;
        if (input && !hasValue(input)) {
            fillInput(input, value);
            filled += 1;
        }
    }

    if (filled > 0) {
        showNotification('Card filled (CVV not auto-filled)', 'success');
    } else {
        showNotification('No matching card fields to fill', 'error');
    }
}

/** 登录填充成功后同页若有 OTP 框则链式填 2FA（合并登录+OTP 表单场景）。 */
export async function maybeChainFillTotp() {
    if (!state.currentSettings.autoFillTotpAfterLogin) return;
    const input = findTotpInput();
    if (!input || hasValue(input)) return;
    if (!(await isDomainAllowedForAutoFill())) return;

    const { picked } = selectSuggestionWithDefault('totp', state.currentSettings.minMatchStrengthTotp);
    if (!picked) return;

    await requestTotp(picked.item_id, input, true);
}

// Fill input with proper events
// Handle fill command from popup
export function handleFillCommand(credential: FillCredential) {
    fillCredential(credential);
}

export async function copyToClipboard(text: string): Promise<boolean> {
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(text);
            return true;
        }
    } catch {
        // fall through
    }

    try {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        const ok = document.execCommand('copy');
        textarea.remove();
        return ok;
    } catch {
        return false;
    }
}

// Toggle main overlay
