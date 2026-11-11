import type { DetectedForm } from '../formScanner.js';
import type { DomainAssessment } from '../domainPolicy.js';
import { DEFAULT_AUTOFILL_SETTINGS } from '../settings.js';
import type { AutofillSettings } from '../settings.js';
import type { OriginAutofillDefaults } from '../autofillDefaults.js';
import type { SuggestionItem } from './types.js';

/// Shared mutable content-script state. Content sections are separate ES
/// modules, so assignable state lives in one container object (ES module
/// imports of `let` bindings are read-only; object properties are not).
export const state = {
    currentForms: [] as DetectedForm[],
    currentSuggestions: [] as SuggestionItem[],
    autofillOverlay: null as HTMLElement | null,
    inlineIcon: null as HTMLElement | null,
    generatorIcon: null as HTMLElement | null,
    currentSettings: DEFAULT_AUTOFILL_SETTINGS as AutofillSettings,
    saveBar: null as HTMLElement | null,
    visibleSaveKey: null as string | null,
    lastDeclinedSave: null as { username: string; password: string; at: number } | null,
    cachedAssessment: null as { at: number; value: DomainAssessment } | null,
    lastLoginAutofillAttemptAt: 0,
    lastTotpAutofillAttemptAt: 0,
    lastSuggestionsFetchAt: 0,
    suggestionsFetchInFlight: null as Promise<void> | null,
    suggestionsRetryAfterAt: 0,
    currentOriginDefaults: null as OriginAutofillDefaults | null,
    passkeyOverlay: null as HTMLElement | null,
    passkeyOverlayRequestId: null as string | null,
};
