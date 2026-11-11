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
import { escapeHtml, fillInput, hasValue } from './util.js';
import { hideOverlay, toggleOverlay } from './overlay.js';
import { requestFill, requestTotp } from './fillRequests.js';
import { maybeRememberDefault } from './suggestions.js';


export function isLikelyTotpInput(input: HTMLInputElement, cachedFieldName?: string): boolean {
    if (input.autocomplete === 'one-time-code') return true;

    const fieldName = (cachedFieldName ?? input.name ?? input.id ?? '').toLowerCase();
    if (['otp', 'totp', '2fa', 'twofactor', 'verification', 'token', 'mfa'].some((hint) => fieldName.includes(hint))) {
        return true;
    }

    const inputMode = (input.inputMode || '').toLowerCase();
    if (inputMode === 'numeric') {
        const maxLen = input.maxLength;
        if (maxLen >= 4 && maxLen <= 10) return true;
        if (maxLen === 1) return true;
    }

    const aria = (input.getAttribute('aria-label') || '').toLowerCase();
    if (aria.includes('verification') || aria.includes('authenticator') || aria.includes('code') || aria.includes('digit')) {
        return true;
    }

    return false;
}

// Show inline Persona icon next to input field
export function showInlineIcon(input: HTMLInputElement, mode: 'password' | 'totp') {
    // Remove existing icon
    if (state.inlineIcon) {
        state.inlineIcon.remove();
        state.inlineIcon = null;
    }

    // Create icon element
    const icon = document.createElement('div');
    icon.className = 'persona-inline-icon';
    icon.innerHTML = '🛡️';
    icon.title = 'Click to autofill with Persona';
    icon.style.cssText = `
        position: absolute;
        width: 24px;
        height: 24px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 16px;
        z-index: 999999;
        background: white;
        border-radius: 4px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    `;

    // Position the icon
    const rect = input.getBoundingClientRect();
    icon.style.left = `${rect.right + window.scrollX - 28}px`;
    icon.style.top = `${rect.top + window.scrollY + (rect.height - 24) / 2}px`;

    icon.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        showSuggestionsDropdown(input, mode);
    });

    mountPersonaUi(document).root.appendChild(icon);
    state.inlineIcon = icon;

    // Remove icon when input loses focus
    const removeIcon = () => {
        setTimeout(() => {
            if (!icon.matches(':hover')) {
                icon.remove();
                if (state.inlineIcon === icon) {
                    state.inlineIcon = null;
                }
            }
        }, 200);
    };
    input.addEventListener('blur', removeIcon, { once: true });
}

// Show password generator icon on new-password fields (registration forms)

export function showGeneratorIcon(input: HTMLInputElement) {
    // Remove existing generator icon
    if (state.generatorIcon) {
        state.generatorIcon.remove();
        state.generatorIcon = null;
    }

    // Create icon element
    const icon = document.createElement('div');
    icon.className = 'persona-generator-icon';
    icon.innerHTML = '🔑';
    icon.title = 'Generate a secure password';
    icon.style.cssText = `
        position: absolute;
        width: 24px;
        height: 24px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 16px;
        z-index: 999999;
        background: white;
        border-radius: 4px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    `;

    // Position the icon
    const rect = input.getBoundingClientRect();
    icon.style.left = `${rect.right + window.scrollX - 28}px`;
    icon.style.top = `${rect.top + window.scrollY + (rect.height - 24) / 2}px`;

    icon.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        showGeneratorDropdown(input, icon);
    });

    mountPersonaUi(document).root.appendChild(icon);
    state.generatorIcon = icon;

    // Remove icon when input loses focus
    const removeIcon = () => {
        setTimeout(() => {
            if (!icon.matches(':hover')) {
                icon.remove();
                if (state.generatorIcon === icon) {
                    state.generatorIcon = null;
                }
            }
        }, 200);
    };
    input.addEventListener('blur', removeIcon, { once: true });
}

// Show password generator dropdown near input
export function showGeneratorDropdown(input: HTMLInputElement, genIcon: HTMLElement) {
    hideOverlay();

    const dropdown = document.createElement('div');
    dropdown.className = 'persona-generator-dropdown';
    dropdown.style.cssText = `
        position: absolute;
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        z-index: 999999;
        width: 280px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    // Position dropdown
    const rect = input.getBoundingClientRect();
    dropdown.style.left = `${rect.left + window.scrollX}px`;
    dropdown.style.top = `${rect.bottom + window.scrollY + 4}px`;

    // Header
    const header = document.createElement('div');
    header.style.cssText = `
        padding: 12px 16px;
        border-bottom: 1px solid #e2e8f0;
        font-weight: 600;
        color: #1a1a1a;
        display: flex;
        align-items: center;
        gap: 8px;
    `;
    header.innerHTML = '🔑 Generate Password';
    dropdown.appendChild(header);

    // Quick generate button (default settings)
    const quickBtn = document.createElement('button');
    quickBtn.style.cssText = `
        width: 100%;
        padding: 12px 16px;
        border: none;
        border-radius: 0;
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        color: white;
        cursor: pointer;
        font-size: 14px;
        font-weight: 500;
        text-align: left;
    `;
    quickBtn.innerHTML = '🎲 Generate (16 chars, all sets)';
    dropdown.appendChild(quickBtn);

    // Separator
    const sep = document.createElement('div');
    sep.style.cssText = 'height: 1px; background: #e2e8f0; margin: 8px 0;';
    dropdown.appendChild(sep);

    // Custom options
    const optionsDiv = document.createElement('div');
    optionsDiv.style.cssText = 'padding: 12px 16px;';
    optionsDiv.innerHTML = `
        <label style="display: block; margin-bottom: 8px; font-size: 13px; color: #374151;">
            Length: <input type="number" id="gen-length" value="16" min="4" max="128" style="width: 60px; margin-left: 8px; padding: 4px 8px; border: 1px solid #d1d5db; border-radius: 4px;">
        </label>
        <label style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 13px; color: #374151;">
            <input type="checkbox" id="gen-lower" checked> Lowercase
        </label>
        <label style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 13px; color: #374151;">
            <input type="checkbox" id="gen-upper" checked> Uppercase
        </label>
        <label style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 13px; color: #374151;">
            <input type="checkbox" id="gen-digits" checked> Digits
        </label>
        <label style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 13px; color: #374151;">
            <input type="checkbox" id="gen-symbols" checked> Symbols
        </label>
        <label style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 13px; color: #374151;">
            <input type="checkbox" id="gen-pronounceable"> Pronounceable
        </label>
        <label style="display: block; margin-bottom: 8px; font-size: 13px; color: #374151;">
            Passphrase (words): <input type="number" id="gen-words" value="" min="3" max="10" placeholder="3-10 (overrides above)" style="width: 60px; margin-left: 8px; padding: 4px 8px; border: 1px solid #d1d5db; border-radius: 4px;">
        </label>
        <button id="gen-custom" style="width: 100%; padding: 10px; border: 1px solid #e2e8f0; border-radius: 6px; background: white; color: #374151; cursor: pointer; font-size: 13px; font-weight: 500;">Generate Custom</button>
    `;
    dropdown.appendChild(optionsDiv);

    // Status line
    const statusLine = document.createElement('div');
    statusLine.style.cssText = 'padding: 8px 16px; color: #64748b; font-size: 12px; display: none;';
    dropdown.appendChild(statusLine);

    const generateAndFill = async (request: any) => {
        quickBtn.disabled = true;
        (dropdown.querySelector('#gen-custom') as HTMLButtonElement).disabled = true;
        statusLine.style.display = 'block';
        statusLine.textContent = 'Generating…';

        try {
            const response = await chrome.runtime.sendMessage({
                type: 'persona_generate_password',
                request
            });

            if (response?.success && response.data?.password) {
                const password = response.data.password;
                // Fill the target new-password field
                fillInput(input, password);
                // Also fill any other new-password / confirm password fields in the same form
                const form = input.form;
                if (form) {
                    const confirmFields = Array.from(form.querySelectorAll('input[type="password"][autocomplete="new-password"]'))
                        .filter((el): el is HTMLInputElement => el instanceof HTMLInputElement && el !== input);
                    for (const field of confirmFields) {
                        if (!hasValue(field)) fillInput(field, password);
                    }
                }
                statusLine.textContent = 'Generated & filled!';
                statusLine.style.color = '#22c55e';
                setTimeout(() => {
                    dropdown.remove();
                    if (state.generatorIcon === genIcon) state.generatorIcon = null;
                }, 1500);
            } else {
                statusLine.textContent = response?.error || 'Generation failed';
                statusLine.style.color = '#ef4444';
            }
        } catch (error) {
            statusLine.textContent = error instanceof Error ? error.message : 'Generation failed';
            statusLine.style.color = '#ef4444';
        } finally {
            quickBtn.disabled = false;
            (dropdown.querySelector('#gen-custom') as HTMLButtonElement).disabled = false;
        }
    };

    // Quick generate (defaults)
    quickBtn.addEventListener('click', () => {
        generateAndFill({
            length: 16,
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
            pronounceable: false
        });
    });

    // Custom generate
    const customBtn = dropdown.querySelector('#gen-custom') as HTMLButtonElement;
    customBtn.addEventListener('click', () => {
        const length = parseInt((dropdown.querySelector('#gen-length') as HTMLInputElement).value, 10);
        const wordsVal = (dropdown.querySelector('#gen-words') as HTMLInputElement).value;
        const words = wordsVal ? parseInt(wordsVal, 10) : undefined;

        generateAndFill({
            length,
            include_lowercase: (dropdown.querySelector('#gen-lower') as HTMLInputElement).checked,
            include_uppercase: (dropdown.querySelector('#gen-upper') as HTMLInputElement).checked,
            include_digits: (dropdown.querySelector('#gen-digits') as HTMLInputElement).checked,
            include_symbols: (dropdown.querySelector('#gen-symbols') as HTMLInputElement).checked,
            pronounceable: (dropdown.querySelector('#gen-pronounceable') as HTMLInputElement).checked,
            words
        });
    });

    mountPersonaUi(document).root.appendChild(dropdown);
    state.autofillOverlay = dropdown;

    // Close on click outside
    setTimeout(() => {
        document.addEventListener('click', function closeDropdown(e) {
            if (!dropdown.contains(e.target as Node)) {
                dropdown.remove();
                state.autofillOverlay = null;
                if (state.generatorIcon === genIcon) state.generatorIcon = null;
                document.removeEventListener('click', closeDropdown);
            }
        });
    }, 100);
}

// Show suggestions dropdown near input
export function showSuggestionsDropdown(input: HTMLInputElement, mode: 'password' | 'totp') {
    hideOverlay();

    const filtered = state.currentSuggestions.filter((s) => (s.credential_type ?? 'password') === mode);
    if (filtered.length === 0) {
        console.debug('[Persona] No suggestions available');
        return;
    }

    const dropdown = document.createElement('div');
    dropdown.className = 'persona-dropdown';
    dropdown.style.cssText = `
        position: absolute;
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        z-index: 999999;
        min-width: 280px;
        max-height: 300px;
        overflow-y: auto;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    // Position dropdown
    const rect = input.getBoundingClientRect();
    dropdown.style.left = `${rect.left + window.scrollX}px`;
    dropdown.style.top = `${rect.bottom + window.scrollY + 4}px`;

    // Add header
    const header = document.createElement('div');
    header.style.cssText = `
        padding: 12px 16px;
        border-bottom: 1px solid #e2e8f0;
        font-weight: 600;
        color: #1a1a1a;
        display: flex;
        align-items: center;
        gap: 8px;
    `;
    header.innerHTML = '🛡️ Persona';
    dropdown.appendChild(header);

    // Add suggestions
    filtered.forEach((suggestion) => {
        const item = document.createElement('div');
        item.style.cssText = `
            padding: 12px 16px;
            cursor: pointer;
            border-bottom: 1px solid #f1f5f9;
            transition: background 0.15s;
        `;
        item.innerHTML = `
            <div style="font-weight: 500; color: #1a1a1a; margin-bottom: 2px;">${escapeHtml(suggestion.title)}</div>
            <div style="font-size: 13px; color: #64748b;">${escapeHtml(suggestion.username_hint || '')}</div>
        `;

        item.addEventListener('mouseenter', () => {
            item.style.background = '#f8fafc';
        });
        item.addEventListener('mouseleave', () => {
            item.style.background = 'white';
        });

        item.addEventListener('click', () => {
            if ((suggestion.credential_type ?? 'password') === 'totp') {
                void maybeRememberDefault('totp', suggestion.item_id);
                requestTotp(suggestion.item_id, input);
            } else {
                void maybeRememberDefault('password', suggestion.item_id);
                requestFill(suggestion.item_id, input);
            }
            dropdown.remove();
        });

        dropdown.appendChild(item);
    });

    mountPersonaUi(document).root.appendChild(dropdown);
    state.autofillOverlay = dropdown;

    // Close on click outside. Clicks inside the shadow root never reach this
    // document listener (shadowUi stops them at the root), so every click
    // observed here is a genuine outside click even though the event target
    // of anything under the closed root is retargeted away from the dropdown.
    setTimeout(() => {
        document.addEventListener('click', function closeDropdown(e) {
            if (!dropdown.contains(e.target as Node)) {
                dropdown.remove();
                state.autofillOverlay = null;
                document.removeEventListener('click', closeDropdown);
            }
        });
    }, 100);
}

// Request fill from background
