import { observeForms, type DetectedForm, type DetectedField } from './formScanner.js';
import { evaluateDomain, type DomainAssessment, type DomainPolicy } from './domainPolicy.js';
import {
    DEFAULT_AUTOFILL_SETTINGS,
    getAutofillSettings,
    onAutofillSettingsChanged,
    type AutofillSettings
} from './settings.js';
import {
    getAutofillDefaultsForOrigin,
    onAutofillDefaultsChanged,
    setAutofillDefaultsForOrigin,
    type OriginAutofillDefaults
} from './autofillDefaults.js';
import {
    freshTotpWaitMs,
    pickSuggestion,
    shouldWaitForFreshTotp,
    totpCopiedNotice,
    totpFilledNotice
} from './autofillUx.js';
import { extractSaveProposal, type SaveProposal, type SaveScanInput } from './saveDetect.js';
import { planLoginStep } from './loginSteps.js';
import { mountPersonaUi } from './shadowUi.js';
import { isTrustedPasskeyOrigin } from './passkeyOrigin.js';

import { state } from './content/state.js';
import { refreshOriginDefaults, fetchSuggestions, getDomainAssessmentCached } from './content/suggestions.js';
import { maybeAutoFillLogin, handleKeydown, handleInputFocus } from './content/fill.js';
import { handleFillCommand } from './content/fillRequests.js';
import { requestFill, requestTotp } from './content/fillRequests.js';
import { showSearchOverlay, showSuggestionsOverlay } from './content/overlay.js';
import { handlePasskeyPageMessage } from './content/passkeyBridge.js';
import { handleSaveCaptureSubmit, handleSaveCaptureClick, restorePendingSaveBar } from './content/saveBar.js';

function init() {
    void getAutofillSettings().then((settings) => {
        state.currentSettings = settings;
    });
    onAutofillSettingsChanged((settings) => {
        state.currentSettings = settings;
    });
    void refreshOriginDefaults();
    onAutofillDefaultsChanged(() => {
        void refreshOriginDefaults();
    });

    // Listen for status updates from background
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
        if (message?.type === 'persona_status') {
            console.debug('[Persona] Status update', message.status);
            // Unlocking (or connecting) must take effect on the very next
            // focus, so drop the lookup backoff.
            state.suggestionsRetryAfterAt = 0;
            sendResponse({ ok: true });
        }

        // Handle fill command from popup/background
        if (message?.type === 'persona_do_fill') {
            handleFillCommand(message.credential);
            sendResponse({ ok: true });
        }

        if (message?.type === 'persona_popup_fill_password') {
            void requestFill(message.itemId);
            sendResponse({ ok: true });
        }

        // Card fill rides the same request_fill round-trip as logins; the
        // CLI marks the response with a `card` payload and no CVV.
        if (message?.type === 'persona_popup_fill_card') {
            void requestFill(message.itemId);
            sendResponse({ ok: true });
        }

        if (message?.type === 'persona_popup_fill_totp') {
            void requestTotp(message.itemId);
            sendResponse({ ok: true });
        }

        // Handle show suggestions command
        if (message?.type === 'persona_show_suggestions') {
            showSuggestionsOverlay(message.suggestions);
            sendResponse({ ok: true });
        }

        // Handle open search overlay (from global keyboard shortcut)
        if (message?.type === 'persona_open_search') {
            void showSearchOverlay();
            sendResponse({ ok: true });
        }

        return false;
    });

    // Observe forms and report to background
    observeForms((forms) => {
        state.currentForms = [...forms].sort((a, b) => b.score - a.score);
        chrome.runtime.sendMessage({
            type: 'persona_forms_snapshot',
            host: location.host,
            forms
        });

        // If we have login forms, fetch suggestions
        if (forms.some((f) => f.fields.some((field) => field.type === 'password' || field.type === 'totp'))) {
            void fetchSuggestions().then(() => {
                void maybeAutoFillLogin('load');
            });
        }
    });

    // Add keyboard shortcut listener
    document.addEventListener('keydown', handleKeydown);

    // Add focus listener for input fields
    document.addEventListener('focusin', handleInputFocus);

    // Save/update bar capture (bridge protocol v4). Capture phase so
    // preventDefault()-style SPA handlers can't swallow the signal; the
    // values are read synchronously before the page can clear the fields.
    document.addEventListener('submit', handleSaveCaptureSubmit, true);
    document.addEventListener('click', handleSaveCaptureClick, true);

    // Most logins navigate, and the page holding the password is gone after
    // the redirect. The background keeps the captured proposal for this
    // exact origin, so the landing page can re-offer the bar.
    void restorePendingSaveBar();

    // WebAuthn interception requests from the MAIN-world hook (webauthnHook.ts)
    window.addEventListener('message', handlePasskeyPageMessage);

    console.debug('[Persona] Content script initialized');
}

// Start
init();
