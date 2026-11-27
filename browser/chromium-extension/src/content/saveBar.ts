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
import { IS_TOP_FRAME, fillInput } from './util.js';
import { showNotification } from './overlay.js';
import { getDomainAssessmentCached, refreshOriginDefaults } from './suggestions.js';


export const SAVE_DECLINE_COOLDOWN_MS = 10 * 60 * 1000;

export function handleSaveCaptureSubmit(event: Event) {
    const form = event.target as Element | null;
    if (!(form instanceof HTMLFormElement)) return;
    offerSaveForScope(form);
}

export function handleSaveCaptureClick(event: MouseEvent) {
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
export function offerSaveForScope(originEl: Element) {
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

export function collectSaveInputs(scope: Element): SaveScanInput[] {
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

export async function offerSaveBar(proposal: SaveProposal | null) {
    if (!proposal) return;
    if (!state.currentSettings.savePromptEnabled) return;
    // Per-origin "never" from a previous bar interaction.
    if (state.currentOriginDefaults?.savePromptDisabled) return;

    const declined = state.lastDeclinedSave;
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
    if (state.saveBar && state.visibleSaveKey === proposalKey) return;

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
export async function restorePendingSaveBar() {
    // Top frame only: a same-origin iframe would otherwise claim the stash
    // for the same origin and render a second, duplicate bar.
    if (!IS_TOP_FRAME) return;
    if (!state.currentSettings.savePromptEnabled) return;
    // Per-origin "never" wins over anything the background still holds.
    await refreshOriginDefaults();
    if (state.currentOriginDefaults?.savePromptDisabled) {
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

export function hideSaveBar() {
    state.saveBar?.remove();
    state.saveBar = null;
    state.visibleSaveKey = null;
}

export function renderSaveBar(proposal: SaveProposal, updateTarget: { item_id: string; name: string } | null) {
    hideSaveBar();

    const bar = document.createElement('div');
    bar.className = 'persona-save-bar p-save';

    const title = document.createElement('div');
    title.className = 'p-save-title';
    title.textContent = updateTarget ? '更新 Persona 中的登录？' : '保存登录到 Persona？';
    bar.appendChild(title);

    const detail = document.createElement('div');
    detail.className = 'p-save-detail';
    detail.textContent = updateTarget
        ? `${updateTarget.name}${proposal.username ? ` · ${proposal.username}` : ''}`
        : `${proposal.nameHint || location.host}${proposal.username ? ` · ${proposal.username}` : ''}`;
    bar.appendChild(detail);

    // Editable username: detection guesses, the operator confirms. Saving
    // uses whatever stands in the field at confirm time.
    const usernameInput = document.createElement('input');
    usernameInput.className = 'p-input';
    usernameInput.type = 'text';
    usernameInput.value = proposal.username ?? '';
    usernameInput.placeholder = 'username';
    usernameInput.setAttribute('aria-label', 'Username');
    usernameInput.style.marginBottom = '10px';
    usernameInput.addEventListener('input', () => {
        // the dedupe key must track what a confirm would actually save
        state.visibleSaveKey = `${usernameInput.value}|${proposal.password}`;
    });
    bar.appendChild(usernameInput);

    const row = document.createElement('div');
    row.className = 'p-row';
    bar.appendChild(row);

    const confirmBtn = document.createElement('button');
    confirmBtn.className = 'p-btn';
    confirmBtn.textContent = updateTarget ? '更新' : '保存';
    row.appendChild(confirmBtn);

    const neverBtn = document.createElement('button');
    neverBtn.className = 'p-btn secondary';
    neverBtn.textContent = '此站永不';
    row.appendChild(neverBtn);

    const closeBtn = document.createElement('button');
    closeBtn.className = 'p-x';
    closeBtn.style.marginLeft = 'auto';
    closeBtn.style.fontSize = '14px';
    closeBtn.textContent = '×';
    closeBtn.title = 'Dismiss';
    row.appendChild(closeBtn);

    const statusLine = document.createElement('div');
    statusLine.className = 'p-save-status';
    bar.appendChild(statusLine);

    const decline = () => {
        state.lastDeclinedSave = {
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
        statusLine.classList.add('show');
        statusLine.textContent = '';

        const editedUsername = usernameInput.value;
        void chrome.runtime.sendMessage({
            type: 'persona_save_credential',
            request: {
                origin: location.origin,
                user_gesture: true,
                item_id: updateTarget?.item_id,
                username: editedUsername === '' ? undefined : editedUsername,
                password: proposal.password,
                name_hint: proposal.nameHint
            }
        })
            .then((response) => {
                if (response?.success) {
                    title.textContent = updateTarget ? '已更新 ✓' : '已保存 ✓';
                    detail.textContent = response.data?.name || '';
                    void chrome.runtime.sendMessage({ type: 'persona_clear_pending_save' }).catch(() => null);
                    statusLine.classList.remove('show');
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
    state.saveBar = bar;
    state.visibleSaveKey = `${proposal.username ?? ''}|${proposal.password}`;
}

