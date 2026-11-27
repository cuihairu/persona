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
import { requestFill, requestTotp } from './fillRequests.js';
import { maybeRememberDefault } from './suggestions.js';


export function toggleOverlay() {
    if (state.autofillOverlay) {
        hideOverlay();
    } else {
        showSuggestionsOverlay(state.currentSuggestions);
    }
}

// Show suggestions overlay
export function showSuggestionsOverlay(suggestions: SuggestionItem[]) {
    hideOverlay();

    const overlay = document.createElement('div');
    overlay.className = 'persona-overlay p-panel';
    overlay.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 999999;
        width: 320px;
    `;

    // Header
    const header = document.createElement('div');
    header.className = 'p-head';
    header.innerHTML = `
        <div class="p-title">🛡️ ${chrome.i18n.getMessage('overlayBrandTitle')}</div>
        <button id="persona-close" class="p-x">×</button>
    `;
    overlay.appendChild(header);

    // Content
    const content = document.createElement('div');
    content.className = 'p-body';

    if (suggestions.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'p-empty';
        empty.textContent = chrome.i18n.getMessage('overlayNoCredentials');
        content.appendChild(empty);
    } else {
        suggestions.forEach((suggestion) => {
            const item = document.createElement('div');
            item.className = 'p-item';
            const t = document.createElement('div');
            t.className = 't';
            t.textContent = suggestion.title;
            const s = document.createElement('div');
            s.className = 's';
            s.textContent = suggestion.username_hint || '';
            item.appendChild(t);
            item.appendChild(s);

            item.addEventListener('click', () => {
                if ((suggestion.credential_type ?? 'password') === 'totp') {
                    void maybeRememberDefault('totp', suggestion.item_id);
                    requestTotp(suggestion.item_id);
                } else {
                    void maybeRememberDefault('password', suggestion.item_id);
                    requestFill(suggestion.item_id);
                }
                hideOverlay();
            });

            content.appendChild(item);
        });
    }

    overlay.appendChild(content);
    mountPersonaUi(document).root.appendChild(overlay);
    state.autofillOverlay = overlay;

    // Close button (inside the shadow root — query the overlay subtree, not
    // the document)
    overlay.querySelector('#persona-close')?.addEventListener('click', hideOverlay);
}

// Mini search overlay (Batch C): centered modal with fuzzy search across
// all suggestions for the current origin. Opened via global Ctrl+Shift+Y.
export function showSearchOverlay() {
    hideOverlay();

    const overlay = document.createElement('div');
    overlay.className = 'persona-search-overlay p-panel';
    overlay.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        z-index: 999999;
        width: 420px;
        max-width: calc(100vw - 40px);
    `;

    // Header with search input
    const header = document.createElement('div');
    header.className = 'p-head';

    const title = document.createElement('div');
    title.className = 'p-title';
    title.innerHTML = `🔍 ${chrome.i18n.getMessage('overlaySearchTitle')}`;
    header.appendChild(title);

    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.placeholder = chrome.i18n.getMessage('overlaySearchPlaceholder');
    searchInput.className = 'p-searchbox';
    header.appendChild(searchInput);

    const closeBtn = document.createElement('button');
    closeBtn.textContent = '×';
    closeBtn.className = 'p-x';
    closeBtn.addEventListener('click', hideOverlay);
    header.appendChild(closeBtn);

    overlay.appendChild(header);

    // Content area with filtered suggestions
    const content = document.createElement('div');
    content.className = 'p-body';
    content.style.maxHeight = '360px';
    overlay.appendChild(content);

    const renderResults = (query: string) => {
        const q = query.trim().toLowerCase();
        const filtered = state.currentSuggestions.filter((s) => {
            const title = (s.title || '').toLowerCase();
            const username = (s.username_hint || '').toLowerCase();
            return !q || title.includes(q) || username.includes(q);
        });

        content.replaceChildren();
        if (filtered.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'p-empty';
            empty.textContent = q ? chrome.i18n.getMessage('overlayNoMatches') : chrome.i18n.getMessage('overlayNoCredentialsAny');
            content.appendChild(empty);
            return;
        }

        filtered.forEach((suggestion) => {
            const item = document.createElement('div');
            item.className = 'p-item';
            const kind = suggestion.credential_type ?? 'password';
            const typeLabel = kind === 'totp' ? '2FA' : kind === 'bank_card' ? 'CARD' : 'LOGIN';

            const t = document.createElement('div');
            t.className = 't';
            t.textContent = suggestion.title;
            const s = document.createElement('div');
            s.className = 's';
            const chip = document.createElement('span');
            chip.className = 'p-chip';
            chip.textContent = typeLabel;
            s.appendChild(chip);
            if (suggestion.username_hint) s.appendChild(document.createTextNode(suggestion.username_hint));
            item.appendChild(t);
            item.appendChild(s);

            item.addEventListener('click', () => {
                if (kind === 'totp') {
                    void maybeRememberDefault('totp', suggestion.item_id);
                    requestTotp(suggestion.item_id);
                } else if (kind === 'bank_card') {
                    void requestFill(suggestion.item_id);
                } else {
                    void maybeRememberDefault('password', suggestion.item_id);
                    requestFill(suggestion.item_id);
                }
                hideOverlay();
            });

            content.appendChild(item);
        });
    };

    // Initial render
    renderResults('');

    // Search input handler
    searchInput.addEventListener('input', (e) => {
        renderResults((e.target as HTMLInputElement).value);
    });

    // Focus search input
    searchInput.focus();

    // Keyboard navigation
    searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            hideOverlay();
        }
        if (e.key === 'Enter') {
            const first = content.querySelector('.p-item');
            if (first) {
                (first as HTMLElement).click();
            }
        }
    });

    mountPersonaUi(document).root.appendChild(overlay);
    state.autofillOverlay = overlay;

    // Close on click outside
    setTimeout(() => {
        document.addEventListener('click', function closeSearch(e) {
            if (!overlay.contains(e.target as Node)) {
                hideOverlay();
                document.removeEventListener('click', closeSearch);
            }
        });
    }, 100);
}

// Hide overlay
export function hideOverlay() {
    if (state.autofillOverlay) {
        state.autofillOverlay.remove();
        state.autofillOverlay = null;
    }
    if (state.inlineIcon) {
        state.inlineIcon.remove();
        state.inlineIcon = null;
    }
}

// Show notification
export function showNotification(message: string, type: 'success' | 'error') {
    const notification = document.createElement('div');
    notification.className = `p-toast ${type === 'success' ? 'ok' : 'err'}`;
    notification.textContent = message;

    // The persona-slide-in keyframes + toast classes ship once inside the
    // shadow root (shadowUi.ts) — no stylesheet in document.head.
    mountPersonaUi(document).root.appendChild(notification);

    setTimeout(() => {
        notification.remove();
    }, 3000);
}
