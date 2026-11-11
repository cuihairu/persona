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

const POLICY_MESSAGE_CACHE_MS = 10_000;
// Backoff after a lookup that came back empty or failed — see fetchSuggestions.
const EMPTY_SUGGESTIONS_BACKOFF_MS = 30_000;
const FAILED_SUGGESTIONS_BACKOFF_MS = 10_000;
import { escapeHtml } from './util.js';


export async function refreshOriginDefaults() {
    state.currentOriginDefaults = await getAutofillDefaultsForOrigin(location.origin).catch(() => null);
}

export async function maybeRememberDefault(mode: 'password' | 'totp', itemId: string) {
    const suggestionsForKind = state.currentSuggestions.filter((s) => (s.credential_type ?? 'password') === mode);
    if (suggestionsForKind.length <= 1) return;

    const already =
        mode === 'totp'
            ? state.currentOriginDefaults?.totpItemId === itemId
            : state.currentOriginDefaults?.passwordItemId === itemId;
    if (already) return;

    const patch = mode === 'totp' ? { totpItemId: itemId } : { passwordItemId: itemId };
    await setAutofillDefaultsForOrigin(location.origin, patch).catch(() => null);
    void refreshOriginDefaults();
}

// Fetch suggestions from background
export async function fetchSuggestions() {
    const now = Date.now();
    if (state.suggestionsFetchInFlight) return state.suggestionsFetchInFlight;
    if (now - state.lastSuggestionsFetchAt < 1500) return;
    if (now < state.suggestionsRetryAfterAt) return;

    state.suggestionsFetchInFlight = (async () => {
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'persona_get_suggestions',
                origin: location.origin
            });

            if (response?.success && response.data?.items) {
                state.currentSuggestions = response.data.items;
                console.debug('[Persona] Got suggestions:', state.currentSuggestions.length);
                // Nothing for this origin (or the bridge is locked): every
                // lookup spawns a `persona bridge` process, so back off
                // instead of re-asking on each focus. Unlocking Persona clears
                // the backoff immediately (see the status listener).
                state.suggestionsRetryAfterAt =
                    Date.now() + (state.currentSuggestions.length === 0 ? EMPTY_SUGGESTIONS_BACKOFF_MS : 0);
            } else {
                state.suggestionsRetryAfterAt = Date.now() + FAILED_SUGGESTIONS_BACKOFF_MS;
            }
        } catch (error) {
            console.error('[Persona] Failed to fetch suggestions:', error);
            state.suggestionsRetryAfterAt = Date.now() + FAILED_SUGGESTIONS_BACKOFF_MS;
        } finally {
            state.lastSuggestionsFetchAt = Date.now();
            state.suggestionsFetchInFlight = null;
        }
    })();

    return state.suggestionsFetchInFlight;
}

export async function getDomainAssessmentCached(): Promise<DomainAssessment | null> {
    const now = Date.now();
    if (state.cachedAssessment && now - state.cachedAssessment.at < POLICY_MESSAGE_CACHE_MS) {
        return state.cachedAssessment.value;
    }

    const policies = await chrome.runtime
        .sendMessage({ type: 'persona_domain_policies_get' })
        .then((value) => (Array.isArray(value) ? (value as DomainPolicy[]) : []))
        .catch(() => [] as DomainPolicy[]);

    const assessment = evaluateDomain(location.host, policies);
    state.cachedAssessment = { at: now, value: assessment };
    return assessment;
}

export async function isDomainAllowedForAutoFill(): Promise<boolean> {
    const assessment = await getDomainAssessmentCached();
    if (!assessment) return false;
    if (assessment.risk === 'blocked' || assessment.risk === 'suspicious') return false;
    if (state.currentSettings.requireTrustedDomain && assessment.risk !== 'trusted') return false;
    return true;
}

