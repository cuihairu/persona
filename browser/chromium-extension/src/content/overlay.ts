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
import { escapeHtml } from './util.js';
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
    overlay.className = 'persona-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: white;
        border-radius: 12px;
        box-shadow: 0 8px 30px rgba(0,0,0,0.2);
        z-index: 999999;
        width: 320px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    // Header
    const header = document.createElement('div');
    header.style.cssText = `
        padding: 16px;
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        border-radius: 12px 12px 0 0;
        color: white;
        display: flex;
        justify-content: space-between;
        align-items: center;
    `;
    header.innerHTML = `
        <div style="display: flex; align-items: center; gap: 8px; font-weight: 600;">
            🛡️ Persona
        </div>
        <button id="persona-close" style="
            background: none;
            border: none;
            color: white;
            cursor: pointer;
            font-size: 18px;
            padding: 4px;
        ">×</button>
    `;
    overlay.appendChild(header);

    // Content
    const content = document.createElement('div');
    content.style.cssText = `padding: 8px 0; max-height: 400px; overflow-y: auto;`;

    if (suggestions.length === 0) {
        content.innerHTML = `
            <div style="padding: 24px; text-align: center; color: #64748b;">
                No saved credentials for this site
            </div>
        `;
    } else {
        suggestions.forEach((suggestion) => {
            const item = document.createElement('div');
            item.style.cssText = `
                padding: 12px 16px;
                cursor: pointer;
                border-bottom: 1px solid #f1f5f9;
                transition: background 0.15s;
            `;
            item.innerHTML = `
                <div style="font-weight: 500; color: #1a1a1a;">${escapeHtml(suggestion.title)}</div>
                <div style="font-size: 13px; color: #64748b; margin-top: 2px;">${escapeHtml(suggestion.username_hint || '')}</div>
            `;

            item.addEventListener('mouseenter', () => item.style.background = '#f8fafc');
            item.addEventListener('mouseleave', () => item.style.background = 'white');
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
    overlay.className = 'persona-search-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: white;
        border-radius: 12px;
        box-shadow: 0 8px 30px rgba(0,0,0,0.25);
        z-index: 999999;
        width: 420px;
        max-width: calc(100vw - 40px);
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    // Header with search input
    const header = document.createElement('div');
    header.style.cssText = `
        padding: 16px;
        border-bottom: 1px solid #e2e8f0;
        display: flex;
        align-items: center;
        gap: 12px;
    `;
    header.innerHTML = `
        <div style="display: flex; align-items: center; gap: 8px; font-weight: 600; color: #1a1a1a;">
            🔍 Persona Search
        </div>
    `;

    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.placeholder = 'Search credentials…';
    searchInput.style.cssText = `
        flex: 1;
        padding: 10px 14px;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        font-size: 14px;
        outline: none;
        background: #f8fafc;
    `;
    header.appendChild(searchInput);

    const closeBtn = document.createElement('button');
    closeBtn.textContent = '×';
    closeBtn.style.cssText = `
        background: none;
        border: none;
        color: #64748b;
        cursor: pointer;
        font-size: 20px;
        padding: 4px;
        line-height: 1;
    `;
    closeBtn.addEventListener('click', hideOverlay);
    header.appendChild(closeBtn);

    overlay.appendChild(header);

    // Content area with filtered suggestions
    const content = document.createElement('div');
    content.style.cssText = `padding: 8px 0; max-height: 360px; overflow-y: auto;`;
    overlay.appendChild(content);

    const renderResults = (query: string) => {
        const q = query.trim().toLowerCase();
        const filtered = state.currentSuggestions.filter((s) => {
            const title = (s.title || '').toLowerCase();
            const username = (s.username_hint || '').toLowerCase();
            return !q || title.includes(q) || username.includes(q);
        });

        content.innerHTML = '';
        if (filtered.length === 0) {
            content.innerHTML = `
                <div style="padding: 24px; text-align: center; color: #64748b;">
                    ${q ? 'No matches' : 'No saved credentials'}
                </div>
            `;
            return;
        }

        filtered.forEach((suggestion) => {
            const item = document.createElement('div');
            item.style.cssText = `
                padding: 12px 16px;
                cursor: pointer;
                border-bottom: 1px solid #f1f5f9;
                transition: background 0.15s;
            `;
            const kind = suggestion.credential_type ?? 'password';
            const typeLabel = kind === 'totp' ? '2FA' : kind === 'bank_card' ? 'CARD' : 'LOGIN';
            item.innerHTML = `
                <div style="font-weight: 500; color: #1a1a1a; margin-bottom: 2px;">
                    ${escapeHtml(suggestion.title)}
                </div>
                <div style="font-size: 12px; color: #64748b; display: flex; align-items: center; gap: 8px;">
                    <span style="font-weight: 600; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 10px;">${typeLabel}</span>
                    ${suggestion.username_hint ? escapeHtml(suggestion.username_hint) : ''}
                </div>
            `;

            item.addEventListener('mouseenter', () => item.style.background = '#f8fafc');
            item.addEventListener('mouseleave', () => item.style.background = 'white');
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
            const items = content.querySelectorAll('[style*="cursor: pointer"]');
            if (items.length > 0) {
                (items[0] as HTMLElement).click();
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
    notification.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 12px 20px;
        background: ${type === 'success' ? '#22c55e' : '#ef4444'};
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        animation: persona-slide-in 0.3s ease;
    `;
    notification.textContent = message;

    // The persona-slide-in keyframes ship once inside the shadow root
    // (shadowUi.ts) — no stylesheet in document.head.
    mountPersonaUi(document).root.appendChild(notification);

    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// HTML escape helper
