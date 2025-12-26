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
    type OriginAutofillDefaults
} from './autofillDefaults';

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
}

// Current page state
let currentForms: DetectedForm[] = [];
let currentSuggestions: SuggestionItem[] = [];
let autofillOverlay: HTMLElement | null = null;
let currentSettings: AutofillSettings = DEFAULT_AUTOFILL_SETTINGS;

const POLICY_MESSAGE_CACHE_MS = 10_000;
let cachedAssessment: { at: number; value: DomainAssessment } | null = null;
let lastLoginAutofillAttemptAt = 0;
let lastTotpAutofillAttemptAt = 0;
let lastSuggestionsFetchAt = 0;
let suggestionsFetchInFlight: Promise<void> | null = null;
let currentOriginDefaults: OriginAutofillDefaults | null = null;

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

        if (message?.type === 'persona_popup_fill_totp') {
            void requestTotp(message.itemId);
            sendResponse({ ok: true });
        }

        // Handle show suggestions command
        if (message?.type === 'persona_show_suggestions') {
            showSuggestionsOverlay(message.suggestions);
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

    console.debug('[Persona] Content script initialized');
}

async function refreshOriginDefaults() {
    currentOriginDefaults = await getAutofillDefaultsForOrigin(location.origin).catch(() => null);
}

// Fetch suggestions from background
async function fetchSuggestions() {
    const now = Date.now();
    if (suggestionsFetchInFlight) return suggestionsFetchInFlight;
    if (now - lastSuggestionsFetchAt < 1500) return;

    suggestionsFetchInFlight = (async () => {
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'persona_get_suggestions',
                origin: location.origin
            });

            if (response?.success && response.data?.items) {
                currentSuggestions = response.data.items;
                console.debug('[Persona] Got suggestions:', currentSuggestions.length);
            }
        } catch (error) {
            console.error('[Persona] Failed to fetch suggestions:', error);
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

async function selectSuggestionWithDefault(mode: 'password' | 'totp', minStrength: number): Promise<SuggestionItem | null> {
    const filtered = currentSuggestions
        .filter((s) => (s.credential_type ?? 'password') === mode)
        .filter((s) => (typeof s.match_strength === 'number' ? s.match_strength : 0) >= minStrength)
        .sort((a, b) => b.match_strength - a.match_strength);

    if (filtered.length === 0) return null;
    if (filtered.length === 1) return filtered[0];

    const wantedId = mode === 'totp' ? currentOriginDefaults?.totpItemId : currentOriginDefaults?.passwordItemId;
    if (!wantedId) return null;

    return filtered.find((s) => s.item_id === wantedId) ?? null;
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

async function maybeAutoFillLogin(trigger: 'load' | 'focus', focusedInput?: HTMLInputElement) {
    if (trigger === 'load' && !currentSettings.autoFillLoginOnLoad) return;
    if (trigger === 'focus' && !currentSettings.autoFillLoginOnFocus) return;

    const now = Date.now();
    if (now - lastLoginAutofillAttemptAt < 1500) return;

    if (!(await isDomainAllowedForAutoFill())) return;

    const { usernameInput, passwordInput } = getBestLoginInputs();
    if (!passwordInput) return;
    if (hasValue(passwordInput)) return;

    const typedUsername = usernameInput?.value?.trim();
    const suggestion = await selectLoginSuggestion(currentSettings.minMatchStrengthLogin, typedUsername);
    if (!suggestion) return;

    if (focusedInput && focusedInput.type === 'password' && focusedInput !== passwordInput) {
        return;
    }

    lastLoginAutofillAttemptAt = now;
    await requestFill(suggestion.item_id, usernameInput ?? passwordInput, trigger === 'focus');
}

async function maybeAutoFillTotp(_trigger: 'focus', focusedInput?: HTMLInputElement) {
    if (!currentSettings.autoFillTotpOnFocus) return;

    const now = Date.now();
    if (now - lastTotpAutofillAttemptAt < 1500) return;

    if (!(await isDomainAllowedForAutoFill())) return;

    const suggestion = await selectSuggestionWithDefault('totp', currentSettings.minMatchStrengthTotp);
    if (!suggestion) return;

    if (focusedInput && hasValue(focusedInput)) return;

    lastTotpAutofillAttemptAt = now;
    await requestTotp(suggestion.item_id, focusedInput, true);
}

// Handle keyboard shortcuts
function handleKeydown(event: KeyboardEvent) {
    // Ctrl/Cmd + Shift + P to show Persona overlay
    if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key === 'p') {
        event.preventDefault();
        toggleOverlay();
    }

    // Escape to close overlay
    if (event.key === 'Escape' && autofillOverlay) {
        hideOverlay();
    }
}

// Handle focus on input fields
function handleInputFocus(event: FocusEvent) {
    const target = event.target as HTMLElement;
    if (!(target instanceof HTMLInputElement)) return;

    // Check if this is a password or username field
    const fieldType = target.type.toLowerCase();
    const fieldName = (target.name || target.id || '').toLowerCase();

    const isPasswordField = fieldType === 'password';
    const isUsernameField = fieldType === 'text' || fieldType === 'email' ||
        ['user', 'login', 'email', 'identifier'].some(hint => fieldName.includes(hint));
    const isTotpField = isLikelyTotpInput(target, fieldName);

    if ((isPasswordField || isUsernameField) && currentSuggestions.some((s) => (s.credential_type ?? 'password') === 'password')) {
        showInlineIcon(target, 'password');
        void maybeAutoFillLogin('focus', target);
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
    const existingIcon = document.querySelector('.persona-inline-icon');
    if (existingIcon) {
        existingIcon.remove();
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

    document.body.appendChild(icon);

    // Remove icon when input loses focus
    const removeIcon = () => {
        setTimeout(() => {
            if (!icon.matches(':hover')) {
                icon.remove();
            }
        }, 200);
    };
    input.addEventListener('blur', removeIcon, { once: true });
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
                requestTotp(suggestion.item_id, input);
            } else {
                requestFill(suggestion.item_id, input);
            }
            dropdown.remove();
        });

        dropdown.appendChild(item);
    });

    document.body.appendChild(dropdown);
    autofillOverlay = dropdown;

    // Close on click outside
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

async function requestTotp(itemId: string, targetInput?: HTMLInputElement, userGesture = true) {
    try {
        const response = await chrome.runtime.sendMessage({
            type: 'persona_get_totp',
            origin: location.origin,
            itemId,
            userGesture
        });

        if (response?.success && response.data?.code) {
            const code = String(response.data.code);
            const input = targetInput ?? findTotpInput();
            if (input) {
                fillTotpCode(input, code);
                showNotification('2FA code filled', 'success');
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
                    showNotification('2FA code copied', 'success');
                } else {
                    await copyToClipboard(code);
                    showNotification('2FA code copied (fallback)', 'success');
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
                    requestTotp(suggestion.item_id);
                } else {
                    requestFill(suggestion.item_id);
                }
                hideOverlay();
            });

            content.appendChild(item);
        });
    }

    overlay.appendChild(content);
    document.body.appendChild(overlay);
    autofillOverlay = overlay;

    // Close button
    document.getElementById('persona-close')?.addEventListener('click', hideOverlay);
}

// Hide overlay
function hideOverlay() {
    if (autofillOverlay) {
        autofillOverlay.remove();
        autofillOverlay = null;
    }
    document.querySelector('.persona-inline-icon')?.remove();
    document.querySelector('.persona-dropdown')?.remove();
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

    // Add animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes persona-slide-in {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
    `;
    document.head.appendChild(style);

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.remove();
        style.remove();
    }, 3000);
}

// HTML escape helper
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Start
init();
