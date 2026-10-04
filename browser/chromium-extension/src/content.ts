import { observeForms, type DetectedForm, type DetectedField } from './formScanner';
import { evaluateDomain, type DomainAssessment, type DomainPolicy } from './domainPolicy';
import {
    DEFAULT_AUTOFILL_SETTINGS,
    getAutofillSettings,
    onAutofillSettingsChanged,
    type AutofillSettings
} from './settings';
import {
    getAutofillDefaultsForOrigin,
    onAutofillDefaultsChanged,
    setAutofillDefaultsForOrigin,
    type OriginAutofillDefaults
} from './autofillDefaults';
import {
    freshTotpWaitMs,
    pickSuggestion,
    shouldWaitForFreshTotp,
    totpCopiedNotice,
    totpFilledNotice
} from './autofillUx';
import { extractSaveProposal, type SaveProposal, type SaveScanInput } from './saveDetect';
import { planLoginStep } from './loginSteps';
import { mountPersonaUi } from './shadowUi';

interface SuggestionItem {
    item_id: string;
    title: string;
    username_hint?: string;
    match_strength: number;
    credential_type?: string;
}

interface FillCredential {
    username?: string;
    password?: string;
    /** Present for BankCard fills; CVV never appears (bridge copy-only). */
    card?: CardFillData;
}

interface CardFillData {
    card_number: string;
    cardholder_name: string;
    expiry_date: string;
}

// Current page state
let currentForms: DetectedForm[] = [];
let currentSuggestions: SuggestionItem[] = [];
let autofillOverlay: HTMLElement | null = null;
// Inline icon lives in the shadow root; page-side class lookups can't see it.
let inlineIcon: HTMLElement | null = null;
let currentSettings: AutofillSettings = DEFAULT_AUTOFILL_SETTINGS;
// Save/update bar (bridge protocol v4): at most one at a time, plus a short
// decline memory so a dismissed proposal doesn't re-nag on the next submit.
let saveBar: HTMLElement | null = null;
let visibleSaveKey: string | null = null;
let lastDeclinedSave: { username: string; password: string; at: number } | null = null;

const POLICY_MESSAGE_CACHE_MS = 10_000;
let cachedAssessment: { at: number; value: DomainAssessment } | null = null;
let lastLoginAutofillAttemptAt = 0;
let lastTotpAutofillAttemptAt = 0;
let lastSuggestionsFetchAt = 0;
let suggestionsFetchInFlight: Promise<void> | null = null;
// Backoff after a lookup that came back empty or failed — see fetchSuggestions.
const EMPTY_SUGGESTIONS_BACKOFF_MS = 30_000;
const FAILED_SUGGESTIONS_BACKOFF_MS = 10_000;
let suggestionsRetryAfterAt = 0;
let currentOriginDefaults: OriginAutofillDefaults | null = null;

// Frame role (batch B: the content script now runs in every frame).
// `window.top` throws on cross-origin parents, hence the guarded read. Frame
// forms fill themselves — each frame talks to the bridge with its OWN origin,
// which is exactly what the origin binding checks. Only page-level chrome
// (the Ctrl+Shift+P overlay, the post-navigation save-bar restore) belongs to
// the top frame, or one bar/overlay per frame would appear.
const IS_TOP_FRAME = (() => {
    try {
        return window.top === window;
    } catch {
        return false;
    }
})();

// Initialize content script
function init() {
    void getAutofillSettings().then((settings) => {
        currentSettings = settings;
    });
    onAutofillSettingsChanged((settings) => {
        currentSettings = settings;
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
            suggestionsRetryAfterAt = 0;
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
        currentForms = [...forms].sort((a, b) => b.score - a.score);
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

async function refreshOriginDefaults() {
    currentOriginDefaults = await getAutofillDefaultsForOrigin(location.origin).catch(() => null);
}

async function maybeRememberDefault(mode: 'password' | 'totp', itemId: string) {
    const suggestionsForKind = currentSuggestions.filter((s) => (s.credential_type ?? 'password') === mode);
    if (suggestionsForKind.length <= 1) return;

    const already =
        mode === 'totp'
            ? currentOriginDefaults?.totpItemId === itemId
            : currentOriginDefaults?.passwordItemId === itemId;
    if (already) return;

    const patch = mode === 'totp' ? { totpItemId: itemId } : { passwordItemId: itemId };
    await setAutofillDefaultsForOrigin(location.origin, patch).catch(() => null);
    void refreshOriginDefaults();
}

// Fetch suggestions from background
async function fetchSuggestions() {
    const now = Date.now();
    if (suggestionsFetchInFlight) return suggestionsFetchInFlight;
    if (now - lastSuggestionsFetchAt < 1500) return;
    if (now < suggestionsRetryAfterAt) return;

    suggestionsFetchInFlight = (async () => {
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'persona_get_suggestions',
                origin: location.origin
            });

            if (response?.success && response.data?.items) {
                currentSuggestions = response.data.items;
                console.debug('[Persona] Got suggestions:', currentSuggestions.length);
                // Nothing for this origin (or the bridge is locked): every
                // lookup spawns a `persona bridge` process, so back off
                // instead of re-asking on each focus. Unlocking Persona clears
                // the backoff immediately (see the status listener).
                suggestionsRetryAfterAt =
                    Date.now() + (currentSuggestions.length === 0 ? EMPTY_SUGGESTIONS_BACKOFF_MS : 0);
            } else {
                suggestionsRetryAfterAt = Date.now() + FAILED_SUGGESTIONS_BACKOFF_MS;
            }
        } catch (error) {
            console.error('[Persona] Failed to fetch suggestions:', error);
            suggestionsRetryAfterAt = Date.now() + FAILED_SUGGESTIONS_BACKOFF_MS;
        } finally {
            lastSuggestionsFetchAt = Date.now();
            suggestionsFetchInFlight = null;
        }
    })();

    return suggestionsFetchInFlight;
}

async function getDomainAssessmentCached(): Promise<DomainAssessment | null> {
    const now = Date.now();
    if (cachedAssessment && now - cachedAssessment.at < POLICY_MESSAGE_CACHE_MS) {
        return cachedAssessment.value;
    }

    const policies = await chrome.runtime
        .sendMessage({ type: 'persona_domain_policies_get' })
        .then((value) => (Array.isArray(value) ? (value as DomainPolicy[]) : []))
        .catch(() => [] as DomainPolicy[]);

    const assessment = evaluateDomain(location.host, policies);
    cachedAssessment = { at: now, value: assessment };
    return assessment;
}

async function isDomainAllowedForAutoFill(): Promise<boolean> {
    const assessment = await getDomainAssessmentCached();
    if (!assessment) return false;
    if (assessment.risk === 'blocked' || assessment.risk === 'suspicious') return false;
    if (currentSettings.requireTrustedDomain && assessment.risk !== 'trusted') return false;
    return true;
}

function isFillableInput(input: HTMLInputElement): boolean {
    if (input.disabled || input.readOnly) return false;
    const style = window.getComputedStyle(input);
    if (style.display === 'none' || style.visibility === 'hidden') return false;
    if (input.getClientRects().length === 0) return false;
    return true;
}

/** 唯一命中/有默认则返回；多候选无默认返回 ambiguous，调用方弹选择器。 */
function selectSuggestionWithDefault(
    mode: 'password' | 'totp',
    minStrength: number
): { picked: SuggestionItem | null; ambiguous: boolean } {
    const wantedId = mode === 'totp' ? currentOriginDefaults?.totpItemId : currentOriginDefaults?.passwordItemId;
    return pickSuggestion(currentSuggestions, mode, minStrength, wantedId);
}

function normalizeUsername(value: string): string {
    return value.trim().toLowerCase();
}

function doesUsernameMatchHint(typedUsername: string, hint: string): boolean {
    const typed = normalizeUsername(typedUsername);
    const candidate = normalizeUsername(hint);
    if (!typed || !candidate) return false;
    if (typed === candidate) return true;
    if (typed.includes(candidate) || candidate.includes(typed)) return true;
    return false;
}

async function selectLoginSuggestion(minStrength: number, typedUsername?: string): Promise<SuggestionItem | null> {
    const filtered = currentSuggestions
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

    const wantedId = currentOriginDefaults?.passwordItemId;
    if (!wantedId) return null;
    return filtered.find((s) => s.item_id === wantedId) ?? null;
}

function getBestLoginInputs(): { usernameInput?: HTMLInputElement; passwordInput?: HTMLInputElement } {
    for (const form of currentForms) {
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
async function fillUsernameStep(itemId: string, input: HTMLInputElement, userGesture: boolean) {
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
function findIdentityInput(focusedInput?: HTMLInputElement): HTMLInputElement | null {
    if (focusedInput instanceof HTMLInputElement && isFillableInput(focusedInput) &&
        focusedInput.type.toLowerCase() !== 'password') {
        const kind = classifyIdentityInput(focusedInput);
        if (kind !== 'none') return focusedInput;
    }

    for (const form of currentForms) {
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

function classifyIdentityInput(input: HTMLInputElement): 'username' | 'email' | 'text' | 'none' {
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

async function maybeAutoFillLogin(trigger: 'load' | 'focus', focusedInput?: HTMLInputElement) {
    if (trigger === 'load' && !currentSettings.autoFillLoginOnLoad) return;
    if (trigger === 'focus' && !currentSettings.autoFillLoginOnFocus) return;

    const now = Date.now();
    if (now - lastLoginAutofillAttemptAt < 1500) return;

    if (!(await isDomainAllowedForAutoFill())) return;

    const { usernameInput, passwordInput } = getBestLoginInputs();
    const typedUsername = usernameInput?.value?.trim();
    const suggestion = await selectLoginSuggestion(currentSettings.minMatchStrengthLogin, typedUsername);
    if (!suggestion) return;

    if (passwordInput) {
        if (hasValue(passwordInput)) return;
        if (focusedInput && focusedInput.type === 'password' && focusedInput !== passwordInput) {
            return;
        }
        lastLoginAutofillAttemptAt = now;
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

    lastLoginAutofillAttemptAt = now;
    await fillUsernameStep(suggestion.item_id, identityInput!, trigger === 'focus');
}

async function maybeAutoFillTotp(_trigger: 'focus', focusedInput?: HTMLInputElement) {
    if (!currentSettings.autoFillTotpOnFocus) return;

    const now = Date.now();
    if (now - lastTotpAutofillAttemptAt < 1500) return;

    if (!(await isDomainAllowedForAutoFill())) return;

    const { picked, ambiguous } = selectSuggestionWithDefault('totp', currentSettings.minMatchStrengthTotp);
    if (!picked) {
        // 多候选且无默认记忆：不再静默失败，就地弹出选择下拉
        if (ambiguous && focusedInput && !hasValue(focusedInput)) {
            lastTotpAutofillAttemptAt = now;
            showSuggestionsDropdown(focusedInput, 'totp');
        }
        return;
    }

    if (focusedInput && hasValue(focusedInput)) return;

    lastTotpAutofillAttemptAt = now;
    await requestTotp(picked.item_id, focusedInput, true);
}

// Handle keyboard shortcuts
function handleKeydown(event: KeyboardEvent) {
    // Ctrl/Cmd + Shift + P to show Persona overlay (top frame only — see
    // IS_TOP_FRAME: key events inside a cross-origin iframe never reach the
    // parent document, and one overlay per frame would be noise).
    if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key === 'p' && IS_TOP_FRAME) {
        event.preventDefault();
        toggleOverlay();
    }

    // Escape to close overlay
    if (event.key === 'Escape' && autofillOverlay) {
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
async function ensureSuggestionsThenAutofill(
    trigger: 'load' | 'focus',
    focusedInput?: HTMLInputElement
) {
    if (currentSuggestions.length === 0) {
        await fetchSuggestions();
    }
    await maybeAutoFillLogin(trigger, focusedInput);
}

// Handle focus on input fields
function handleInputFocus(event: FocusEvent) {
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
        if (currentSuggestions.some((s) => (s.credential_type ?? 'password') === 'password')) {
            showInlineIcon(target, 'password');
        }
        // A username-only step (multi-step login) has no password field, so
        // the load-time scan never fetched suggestions for this frame. A
        // focus is a real user action: fetch once, then let the planner decide.
        void ensureSuggestionsThenAutofill('focus', target);
    }
    // Show password generator icon on registration forms (new-password field)
    if (isNewPasswordField && currentSettings.savePromptEnabled) {
        showGeneratorIcon(target);
    }
    if (isTotpField && currentSuggestions.some((s) => (s.credential_type ?? 'password') === 'totp')) {
        showInlineIcon(target, 'totp');
        void maybeAutoFillTotp('focus', target);
    }
}

function isLikelyTotpInput(input: HTMLInputElement, cachedFieldName?: string): boolean {
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
function showInlineIcon(input: HTMLInputElement, mode: 'password' | 'totp') {
    // Remove existing icon
    if (inlineIcon) {
        inlineIcon.remove();
        inlineIcon = null;
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
    inlineIcon = icon;

    // Remove icon when input loses focus
    const removeIcon = () => {
        setTimeout(() => {
            if (!icon.matches(':hover')) {
                icon.remove();
                if (inlineIcon === icon) {
                    inlineIcon = null;
                }
            }
        }, 200);
    };
    input.addEventListener('blur', removeIcon, { once: true });
}

// Show password generator icon on new-password fields (registration forms)
let generatorIcon: HTMLElement | null = null;

function showGeneratorIcon(input: HTMLInputElement) {
    // Remove existing generator icon
    if (generatorIcon) {
        generatorIcon.remove();
        generatorIcon = null;
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
    generatorIcon = icon;

    // Remove icon when input loses focus
    const removeIcon = () => {
        setTimeout(() => {
            if (!icon.matches(':hover')) {
                icon.remove();
                if (generatorIcon === icon) {
                    generatorIcon = null;
                }
            }
        }, 200);
    };
    input.addEventListener('blur', removeIcon, { once: true });
}

// Show password generator dropdown near input
function showGeneratorDropdown(input: HTMLInputElement, genIcon: HTMLElement) {
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
                    if (generatorIcon === genIcon) generatorIcon = null;
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
    autofillOverlay = dropdown;

    // Close on click outside
    setTimeout(() => {
        document.addEventListener('click', function closeDropdown(e) {
            if (!dropdown.contains(e.target as Node)) {
                dropdown.remove();
                autofillOverlay = null;
                if (generatorIcon === genIcon) generatorIcon = null;
                document.removeEventListener('click', closeDropdown);
            }
        });
    }, 100);
}

// Show suggestions dropdown near input
function showSuggestionsDropdown(input: HTMLInputElement, mode: 'password' | 'totp') {
    hideOverlay();

    const filtered = currentSuggestions.filter((s) => (s.credential_type ?? 'password') === mode);
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
    autofillOverlay = dropdown;

    // Close on click outside. Clicks inside the shadow root never reach this
    // document listener (shadowUi stops them at the root), so every click
    // observed here is a genuine outside click even though the event target
    // of anything under the closed root is retargeted away from the dropdown.
    setTimeout(() => {
        document.addEventListener('click', function closeDropdown(e) {
            if (!dropdown.contains(e.target as Node)) {
                dropdown.remove();
                autofillOverlay = null;
                document.removeEventListener('click', closeDropdown);
            }
        });
    }, 100);
}

// Request fill from background
async function requestFill(itemId: string, targetInput?: HTMLInputElement, userGesture = true) {
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

function sendTotpRequest(itemId: string, userGesture: boolean) {
    return chrome.runtime.sendMessage({
        type: 'persona_get_totp',
        origin: location.origin,
        itemId,
        userGesture
    });
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function requestTotp(itemId: string, targetInput?: HTMLInputElement, userGesture = true) {
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

function findTotpInput(): HTMLInputElement | null {
    const form = currentForms[0];
    const totpField = form?.fields?.find((f) => f.type === 'totp');
    if (totpField?.selector) {
        const el = document.querySelector(totpField.selector);
        if (el instanceof HTMLInputElement) return el;
    }

    const fallback = document.querySelector('input[autocomplete="one-time-code"]');
    return fallback instanceof HTMLInputElement ? fallback : null;
}

function hasValue(input: HTMLInputElement | null | undefined): boolean {
    return Boolean(input?.value?.trim());
}

function isOtpDigitInput(input: HTMLInputElement): boolean {
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

function findOtpGroupInputs(target: HTMLInputElement): HTMLInputElement[] {
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

function fillTotpCode(target: HTMLInputElement, code: string) {
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

function selectFormForTarget(targetInput?: HTMLInputElement): DetectedForm | null {
    if (!currentForms.length) return null;
    if (!targetInput) return currentForms[0];

    for (const form of currentForms) {
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
        for (const form of currentForms) {
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

    return currentForms[0];
}

// Fill credential into form
function fillCredential(credential: FillCredential, targetInput?: HTMLInputElement) {
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
function cardFieldCount(form: DetectedForm): number {
    return form.fields.filter((field) => field.type.startsWith('card_')).length;
}

/**
 * Fill card fields on the page. CVV is deliberately not auto-filled: the
 * bridge never returns it, and injecting it into page DOM would expose it to
 * page scripts — CVV stays a copy-only value end to end.
 */
function fillCard(card: CardFillData) {
    if (!currentForms.length) {
        console.warn('[Persona] No form detected');
        showNotification('No form detected on this page', 'error');
        return;
    }

    // Checkout pages can also host login forms: target the form with the
    // most card fields.
    const form = [...currentForms]
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
async function maybeChainFillTotp() {
    if (!currentSettings.autoFillTotpAfterLogin) return;
    const input = findTotpInput();
    if (!input || hasValue(input)) return;
    if (!(await isDomainAllowedForAutoFill())) return;

    const { picked } = selectSuggestionWithDefault('totp', currentSettings.minMatchStrengthTotp);
    if (!picked) return;

    await requestTotp(picked.item_id, input, true);
}

// Fill input with proper events
function fillInput(input: HTMLInputElement, value: string) {
    // Focus the input
    input.focus();

    // Set value
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype, 'value'
    )?.set;

    if (nativeInputValueSetter) {
        nativeInputValueSetter.call(input, value);
    } else {
        input.value = value;
    }

    // Dispatch events to trigger React/Vue/Angular handlers
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
}

// Handle fill command from popup
function handleFillCommand(credential: FillCredential) {
    fillCredential(credential);
}

async function copyToClipboard(text: string): Promise<boolean> {
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
function toggleOverlay() {
    if (autofillOverlay) {
        hideOverlay();
    } else {
        showSuggestionsOverlay(currentSuggestions);
    }
}

// Show suggestions overlay
function showSuggestionsOverlay(suggestions: SuggestionItem[]) {
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
    autofillOverlay = overlay;

    // Close button (inside the shadow root — query the overlay subtree, not
    // the document)
    overlay.querySelector('#persona-close')?.addEventListener('click', hideOverlay);
}

// Mini search overlay (Batch C): centered modal with fuzzy search across
// all suggestions for the current origin. Opened via global Ctrl+Shift+Y.
function showSearchOverlay() {
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
        const filtered = currentSuggestions.filter((s) => {
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
    autofillOverlay = overlay;

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
function hideOverlay() {
    if (autofillOverlay) {
        autofillOverlay.remove();
        autofillOverlay = null;
    }
    if (inlineIcon) {
        inlineIcon.remove();
        inlineIcon = null;
    }
}

// Show notification
function showNotification(message: string, type: 'success' | 'error') {
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
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============ Passkey selection/confirm UI (bridge protocol v2) ============
//
// The MAIN-world hook (webauthnHook.ts) intercepts navigator.credentials and
// asks this ISOLATED-world script to run the confirmation UI and the bridge
// round-trip. Design rules (docs/PASSKEYS_DESIGN.md §8.2):
//   - create: explicit confirm dialog before any bridge request
//   - assert: candidate picker; no candidates -> no dialog, no request;
//     a single candidate still requires an explicit click (no silent signing)

const PAGE_MESSAGE_SOURCE = 'persona-webauthn';
const CONTENT_MESSAGE_SOURCE = 'persona-webauthn-content';

interface PasskeyCandidate {
    id: string;
    rp_id: string;
    user_name?: string;
    user_display_name?: string;
    identity_name?: string;
    created_at: number;
}

interface PasskeyBridgeReply {
    success: boolean;
    data?: any;
    error?: string;
}

let passkeyOverlay: HTMLElement | null = null;
let passkeyOverlayRequestId: string | null = null;

function handlePasskeyPageMessage(event: MessageEvent) {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== PAGE_MESSAGE_SOURCE) return;

    if (data.type === 'PERSONA_PASSKEY_CANCEL') {
        // The page aborted the ceremony — drop the dialog if it's still up.
        if (passkeyOverlayRequestId === data.requestId) hidePasskeyOverlay();
        return;
    }

    if (data.type === 'PERSONA_PASSKEY_CREATE') {
        void handlePasskeyCreateRequest(data.requestId, data.payload);
        return;
    }

    if (data.type === 'PERSONA_PASSKEY_GET') {
        void handlePasskeyGetRequest(data.requestId, data.payload);
        return;
    }
}

function replyToPage(requestId: string, message: Record<string, unknown>) {
    window.postMessage(
        { source: CONTENT_MESSAGE_SOURCE, requestId, ...message },
        location.origin
    );
}

function fallbackToPage(requestId: string) {
    hidePasskeyOverlay();
    replyToPage(requestId, { type: 'PERSONA_PASSKEY_FALLBACK' });
}

function handlePasskeyCreateRequest(requestId: string, payload: any) {
    // Without a user gesture even the native flow would fail — skip the dialog.
    if (!payload?.user_gesture) {
        fallbackToPage(requestId);
        return;
    }
    const options = payload.request_json ?? {};
    const rpId = options.rp?.id ?? new URL(payload.origin).hostname;
    const userName = options.user?.name ?? 'unknown account';

    showPasskeyDialog({
        title: 'Create a passkey?',
        lines: [
            `Site: ${rpId}`,
            `Origin: ${payload.origin}`,
            `Account: ${userName}`
        ],
        note:
            rpId !== new URL(payload.origin).hostname
                ? `This site signs you in via ${rpId} (a domain it belongs to).`
                : undefined,
        confirmLabel: 'Create',
        onConfirm: async () => {
            const reply: PasskeyBridgeReply = await chrome.runtime
                .sendMessage({ type: 'persona_passkey_create', request: payload })
                .catch((error: Error) => ({ success: false, error: error.message }));
            if (reply?.success) {
                hidePasskeyOverlay();
                replyToPage(requestId, { ok: true, data: reply.data });
            } else {
                replyToPage(requestId, { ok: false, error: reply?.error ?? 'bridge_error' });
            }
        },
        onCancel: () => fallbackToPage(requestId)
    });
}

async function handlePasskeyGetRequest(requestId: string, payload: any) {
    if (!payload?.user_gesture) {
        fallbackToPage(requestId);
        return;
    }

    const listReply: PasskeyBridgeReply = await chrome.runtime
        .sendMessage({ type: 'persona_passkey_list', origin: payload.origin, rpId: payload.rp_id })
        .catch((error: Error) => ({ success: false, error: error.message }));

    // No candidates -> no dialog, no request: straight back to native.
    const candidates: PasskeyCandidate[] = listReply?.success ? (listReply.data?.items ?? []) : [];
    if (candidates.length === 0) {
        fallbackToPage(requestId);
        return;
    }

    showPasskeyDialog({
        title: 'Sign in with a passkey',
        lines: [`Origin: ${payload.origin}`],
        candidates,
        onPick: async (item) => {
            const reply: PasskeyBridgeReply = await chrome.runtime
                .sendMessage({
                    type: 'persona_passkey_assert',
                    request: {
                        origin: payload.origin,
                        user_gesture: payload.user_gesture,
                        item_id: item.id,
                        client_data_json_b64: payload.client_data_json_b64,
                        user_verification: payload.user_verification !== false
                    }
                })
                .catch((error: Error) => ({ success: false, error: error.message }));
            if (reply?.success) {
                hidePasskeyOverlay();
                replyToPage(requestId, { ok: true, data: reply.data });
            } else {
                replyToPage(requestId, { ok: false, error: reply?.error ?? 'bridge_error' });
            }
        },
        onCancel: () => fallbackToPage(requestId)
    });
}

function hidePasskeyOverlay() {
    passkeyOverlay?.remove();
    passkeyOverlay = null;
    passkeyOverlayRequestId = null;
}

function showPasskeyDialog(dialog: {
    title: string;
    lines: string[];
    note?: string;
    confirmLabel?: string;
    candidates?: PasskeyCandidate[];
    onConfirm?: () => Promise<void>;
    onPick?: (item: PasskeyCandidate) => Promise<void>;
    onCancel: () => void;
}) {
    hidePasskeyOverlay();
    passkeyOverlayRequestId = null;

    const backdrop = document.createElement('div');
    backdrop.style.cssText = `
        position: fixed;
        inset: 0;
        background: rgba(15, 23, 42, 0.45);
        z-index: 2147483646;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    const box = document.createElement('div');
    box.style.cssText = `
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: white;
        border-radius: 12px;
        box-shadow: 0 8px 30px rgba(0,0,0,0.3);
        width: 340px;
        max-width: calc(100vw - 32px);
        overflow: hidden;
    `;

    const header = document.createElement('div');
    header.style.cssText = `
        padding: 14px 16px;
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        color: white;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 8px;
    `;
    header.textContent = `🛡️ ${dialog.title}`;
    box.appendChild(header);

    const body = document.createElement('div');
    body.style.cssText = 'padding: 12px 16px; max-height: 320px; overflow-y: auto;';
    for (const line of dialog.lines) {
        const row = document.createElement('div');
        row.style.cssText = 'font-size: 13px; color: #1a1a1a; margin: 4px 0; word-break: break-all;';
        row.textContent = line;
        body.appendChild(row);
    }
    if (dialog.note) {
        const note = document.createElement('div');
        note.style.cssText = 'font-size: 12px; color: #64748b; margin: 8px 0 4px;';
        note.textContent = dialog.note;
        body.appendChild(note);
    }

    if (dialog.candidates) {
        for (const item of dialog.candidates) {
            const row = document.createElement('div');
            row.style.cssText = `
                margin-top: 8px;
                padding: 10px 12px;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                cursor: pointer;
                transition: background 0.15s;
            `;
            const created = new Date(item.created_at * 1000).toISOString().slice(0, 10);
            row.innerHTML = `
                <div style="font-weight: 500; color: #1a1a1a;">${escapeHtml(item.user_display_name ?? item.user_name ?? item.rp_id)}</div>
                <div style="font-size: 12px; color: #64748b; margin-top: 2px;">${escapeHtml(item.user_name ?? '')} · created ${escapeHtml(created)}${item.identity_name ? ` · ${escapeHtml(item.identity_name)}` : ''}</div>
            `;
            row.addEventListener('mouseenter', () => (row.style.background = '#f8fafc'));
            row.addEventListener('mouseleave', () => (row.style.background = 'white'));
            row.addEventListener('click', () => void dialog.onPick?.(item));
            body.appendChild(row);
        }
    }
    box.appendChild(body);

    const footer = document.createElement('div');
    footer.style.cssText = 'display: flex; justify-content: flex-end; gap: 8px; padding: 12px 16px;';

    const cancel = document.createElement('button');
    cancel.textContent = 'Cancel';
    cancel.style.cssText = `
        padding: 8px 14px;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        background: white;
        cursor: pointer;
        font-size: 13px;
    `;

    const proceed = (fn: () => void) => {
        // Every path must resolve the page's pending promise exactly once.
        hidePasskeyOverlay();
        fn();
    };
    cancel.addEventListener('click', () => proceed(dialog.onCancel));
    footer.appendChild(cancel);

    if (dialog.confirmLabel && dialog.onConfirm) {
        const confirm = document.createElement('button');
        confirm.textContent = dialog.confirmLabel;
        confirm.style.cssText = `
            padding: 8px 14px;
            border: none;
            border-radius: 8px;
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            color: white;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
        `;
        confirm.addEventListener('click', () => proceed(dialog.onConfirm!));
        footer.appendChild(confirm);
    }
    box.appendChild(footer);

    backdrop.appendChild(box);
    mountPersonaUi(document).root.appendChild(backdrop);
    passkeyOverlay = backdrop;
}

// ---------------------------------------------------------------------------
// Save/update bar (bridge protocol v4). Capture points: real `submit` events
// plus clicks on submit-ish buttons (SPA logins often have no <form>). The
// proposal only ever becomes a vault write after an explicit bar click — the
// host refuses silent saves (`user_gesture_required`).
// ---------------------------------------------------------------------------

const SAVE_DECLINE_COOLDOWN_MS = 10 * 60 * 1000;

function handleSaveCaptureSubmit(event: Event) {
    const form = event.target as Element | null;
    if (!(form instanceof HTMLFormElement)) return;
    offerSaveForScope(form);
}

function handleSaveCaptureClick(event: MouseEvent) {
    if (event.defaultPrevented) return;
    const target = event.target as Element | null;
    if (!target) return;
    const button = target.closest('button, input[type="submit"], [role="button"]');
    if (!button) return;

    const label = (button.textContent || '').trim().toLowerCase();
    const submitish =
        (button instanceof HTMLButtonElement && button.type === 'submit') ||
        button instanceof HTMLInputElement ||
        /sign in|log in|login|submit|register|sign up|next|continue|保存|登录|注册/.test(label);
    if (!submitish) return;

    offerSaveForScope(button);
}

/**
 * Collect the candidate fields around a trigger point and offer the save bar
 * when they carry a filled password. The scope starts at the trigger itself
 * (a <form> submit) and walks up for SPA buttons until a container holds a
 * filled password field (same idea as the virtual form grouping in
 * formScanner).
 */
function offerSaveForScope(originEl: Element) {
    let node: Element | null = originEl;
    for (let depth = 0; node && depth < 7; depth++) {
        // Cheap gate first: this runs on every page-wide click, and the full
        // scan below forces style resolution per input. Most scopes hold no
        // password field at all.
        if (!node.querySelector('input[type="password"]')) {
            node = node.parentElement;
            continue;
        }
        const inputs = collectSaveInputs(node);
        if (inputs.some((i) => i.inputType === 'password' && i.value)) {
            offerSaveBar(extractSaveProposal(inputs, document.title, location.host));
            return;
        }
        node = node.parentElement;
    }
}

function collectSaveInputs(scope: Element): SaveScanInput[] {
    const candidateTypes = new Set(['text', 'search', 'email', 'tel', 'password', 'number', '']);
    const inputs = Array.from(scope.querySelectorAll('input')).filter((el): el is HTMLInputElement => {
        if (!(el instanceof HTMLInputElement)) return false;
        if (el.disabled) return false;
        const type = (el.getAttribute('type') || 'text').toLowerCase();
        if (!candidateTypes.has(type)) return false;
        const style = window.getComputedStyle(el);
        return style.display !== 'none' && style.visibility !== 'hidden';
    });

    return inputs.map((el) => ({
        inputType: (el.getAttribute('type') || 'text').toLowerCase(),
        autocomplete: (el.getAttribute('autocomplete') || '').toLowerCase(),
        name: el.name || '',
        id: el.id || '',
        placeholder: el.placeholder || '',
        ariaLabel: el.getAttribute('aria-label') || '',
        value: el.value || ''
    }));
}

async function offerSaveBar(proposal: SaveProposal | null) {
    if (!proposal) return;
    if (!currentSettings.savePromptEnabled) return;
    // Per-origin "never" from a previous bar interaction.
    if (currentOriginDefaults?.savePromptDisabled) return;

    const declined = lastDeclinedSave;
    if (
        declined &&
        Date.now() - declined.at < SAVE_DECLINE_COOLDOWN_MS &&
        declined.password === proposal.password &&
        (declined.username ?? '') === (proposal.username ?? '')
    ) {
        return;
    }

    // A click on a submit button and the form's own submit event both fire
    // for one action — don't rebuild (and re-lookup) a bar that's already
    // showing this exact proposal.
    const proposalKey = `${proposal.username ?? ''}|${proposal.password}`;
    if (saveBar && visibleSaveKey === proposalKey) return;

    // Blocked/suspicious domains never see the bar (same gate as fills:
    // writing a password to a lookalike is as harmful as filling one there).
    const assessment = await getDomainAssessmentCached();
    if (assessment && (assessment.risk === 'blocked' || assessment.risk === 'suspicious')) {
        return;
    }

    // Existing item? The host's metadata-only lookup decides whether the
    // bar defaults to "update" instead of "save".
    let updateTarget: { item_id: string; name: string } | null = null;
    try {
        const response = await chrome.runtime.sendMessage({
            type: 'persona_find_for_save',
            origin: location.origin,
            username: proposal.username
        });
        const match = response?.data?.matches?.[0];
        if (match?.item_id) {
            updateTarget = { item_id: match.item_id, name: match.name };
        }
    } catch {
        // Lookup failure just means the bar offers a plain save.
    }

    // Hand the proposal to the background so a redirect (the common case)
    // can re-offer the bar on the landing page. Origin-bound + TTL'd. A
    // duplicate verdict means another frame of this origin already owns the
    // slot and shows the bar — rendering again would stack a second one.
    let duplicate = false;
    try {
        const stashed = await chrome.runtime.sendMessage({
            type: 'persona_stash_pending_save',
            entry: { ...proposal, origin: location.origin, at: Date.now() }
        });
        duplicate = Boolean(stashed?.data?.duplicate);
    } catch {
        // Stash failed (service worker asleep): still show the in-page bar.
    }
    if (duplicate) return;

    renderSaveBar(proposal, updateTarget);
}

/**
 * Post-navigation restore: the previous page stashed the proposal, this
 * page claims it (read-and-clear, so a reload cannot stack bars). Every gate
 * from `offerSaveBar` still applies — the landing page re-runs the policy
 * check and the find_for_save lookup itself.
 */
async function restorePendingSaveBar() {
    // Top frame only: a same-origin iframe would otherwise claim the stash
    // for the same origin and render a second, duplicate bar.
    if (!IS_TOP_FRAME) return;
    if (!currentSettings.savePromptEnabled) return;
    // Per-origin "never" wins over anything the background still holds.
    await refreshOriginDefaults();
    if (currentOriginDefaults?.savePromptDisabled) {
        void chrome.runtime.sendMessage({ type: 'persona_clear_pending_save' }).catch(() => null);
        return;
    }

    let entry: {
        origin: string;
        username?: string;
        password: string;
        scenario: SaveProposal['scenario'];
        nameHint?: string;
    } | null = null;
    try {
        const response = await chrome.runtime.sendMessage({
            type: 'persona_take_pending_save',
            origin: location.origin
        });
        entry = response?.data ?? null;
    } catch {
        return;
    }
    if (!entry?.password) return;

    await offerSaveBar({
        scenario: entry.scenario,
        username: entry.username,
        password: entry.password,
        nameHint: entry.nameHint
    });
}

function hideSaveBar() {
    saveBar?.remove();
    saveBar = null;
    visibleSaveKey = null;
}

function renderSaveBar(proposal: SaveProposal, updateTarget: { item_id: string; name: string } | null) {
    hideSaveBar();

    const bar = document.createElement('div');
    bar.className = 'persona-save-bar';
    bar.style.cssText = `
        position: fixed;
        right: 16px;
        bottom: 16px;
        z-index: 2147483647;
        width: 320px;
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        box-shadow: 0 8px 30px rgba(0,0,0,0.18);
        padding: 14px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 13px;
        color: #1a1a1a;
    `;

    const title = document.createElement('div');
    title.style.cssText = 'font-weight: 600; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;';
    title.textContent = updateTarget ? '更新 Persona 中的登录？' : '保存登录到 Persona？';
    bar.appendChild(title);

    const detail = document.createElement('div');
    detail.style.cssText = 'color: #64748b; margin-bottom: 10px; word-break: break-all;';
    detail.textContent = updateTarget
        ? `${updateTarget.name}${proposal.username ? ` · ${proposal.username}` : ''}`
        : `${proposal.nameHint || location.host}${proposal.username ? ` · ${proposal.username}` : ''}`;
    bar.appendChild(detail);

    const row = document.createElement('div');
    row.style.cssText = 'display: flex; gap: 8px; align-items: center;';
    bar.appendChild(row);

    const confirmBtn = document.createElement('button');
    confirmBtn.style.cssText = `
        padding: 8px 14px;
        border: none;
        border-radius: 8px;
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        color: white;
        cursor: pointer;
        font-size: 13px;
        font-weight: 500;
    `;
    confirmBtn.textContent = updateTarget ? '更新' : '保存';
    row.appendChild(confirmBtn);

    const neverBtn = document.createElement('button');
    neverBtn.style.cssText = `
        padding: 8px 12px;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        background: white;
        cursor: pointer;
        font-size: 13px;
    `;
    neverBtn.textContent = '此站永不';
    row.appendChild(neverBtn);

    const closeBtn = document.createElement('button');
    closeBtn.style.cssText = `
        margin-left: auto;
        padding: 4px 8px;
        border: none;
        background: transparent;
        cursor: pointer;
        font-size: 14px;
        color: #64748b;
    `;
    closeBtn.textContent = '×';
    closeBtn.title = 'Dismiss';
    row.appendChild(closeBtn);

    const statusLine = document.createElement('div');
    statusLine.style.cssText = 'margin-top: 8px; color: #64748b; display: none;';
    bar.appendChild(statusLine);

    const decline = () => {
        lastDeclinedSave = {
            username: proposal.username ?? '',
            password: proposal.password,
            at: Date.now()
        };
        // Drop the background hand-off too: a dismissal must not resurrect
        // the bar on the next page load of this origin.
        void chrome.runtime.sendMessage({ type: 'persona_clear_pending_save' }).catch(() => null);
        hideSaveBar();
    };

    closeBtn.addEventListener('click', decline);

    neverBtn.addEventListener('click', () => {
        void setAutofillDefaultsForOrigin(location.origin, { savePromptDisabled: true })
            .then(() => refreshOriginDefaults())
            .catch(() => null);
        void chrome.runtime.sendMessage({ type: 'persona_clear_pending_save' }).catch(() => null);
        hideSaveBar();
    });

    confirmBtn.addEventListener('click', () => {
        confirmBtn.disabled = true;
        neverBtn.disabled = true;
        confirmBtn.textContent = '保存中…';
        statusLine.style.display = 'block';
        statusLine.textContent = '';

        void chrome.runtime.sendMessage({
            type: 'persona_save_credential',
            request: {
                origin: location.origin,
                user_gesture: true,
                item_id: updateTarget?.item_id,
                username: proposal.username,
                password: proposal.password,
                name_hint: proposal.nameHint
            }
        })
            .then((response) => {
                if (response?.success) {
                    title.textContent = updateTarget ? '已更新 ✓' : '已保存 ✓';
                    detail.textContent = response.data?.name || '';
                    void chrome.runtime.sendMessage({ type: 'persona_clear_pending_save' }).catch(() => null);
                    statusLine.style.display = 'none';
                    confirmBtn.style.display = 'none';
                    neverBtn.style.display = 'none';
                    setTimeout(hideSaveBar, 2500);
                } else {
                    confirmBtn.disabled = false;
                    neverBtn.disabled = false;
                    confirmBtn.textContent = updateTarget ? '更新' : '保存';
                    statusLine.textContent = response?.error || '保存失败';
                }
            })
            .catch((error) => {
                confirmBtn.disabled = false;
                confirmBtn.textContent = updateTarget ? '更新' : '保存';
                statusLine.textContent = error instanceof Error ? error.message : '保存失败';
            });
    });

    mountPersonaUi(document).root.appendChild(bar);
    saveBar = bar;
    visibleSaveKey = `${proposal.username ?? ''}|${proposal.password}`;
}

// Start
init();
