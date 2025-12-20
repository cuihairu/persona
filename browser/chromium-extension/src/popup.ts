import type { BridgeStatus } from './bridge';
import type { DomainAssessment } from './domainPolicy';
import { hello, requestPairingCode, finalizePairing, getPairingState } from './nativeBridge';

const statusEl = document.getElementById('status');
const toggleButton = document.getElementById('toggle');
const endpointInput = document.getElementById('endpoint') as HTMLInputElement | null;
const formsContainer = document.getElementById('forms');
const domainStatusEl = document.getElementById('domainStatus');
const domainReasonsEl = document.getElementById('domainReasons');
const trustButton = document.getElementById('trustDomain');
const blockButton = document.getElementById('blockDomain');
const clearPolicyButton = document.getElementById('clearDomainPolicy');

const pairingStatusEl = document.getElementById('pairingStatus');
const requestPairingButton = document.getElementById('requestPairing');
const pairingCodeInput = document.getElementById('pairingCode') as HTMLInputElement | null;
const pairingHintEl = document.getElementById('pairingHint');
const finalizePairingButton = document.getElementById('finalizePairing');

const autofillStatusEl = document.getElementById('autofillStatus');
const suggestionsEl = document.getElementById('suggestions');

let currentAssessment: DomainAssessment | undefined;
let currentHost: string | undefined;

function describeStatus(status?: BridgeStatus | null) {
    if (!status) return 'Bridge unavailable';
    const ts = new Date(status.lastChecked).toLocaleTimeString();
    const base = status.connected ? 'Connected' : 'Disconnected';
    const detail = status.message ? ` – ${status.message}` : '';
    return `${base}${detail} (${ts})`;
}

function updateStatus(status?: BridgeStatus | null) {
    if (statusEl) {
        statusEl.textContent = describeStatus(status);
    }
    if (endpointInput && status?.endpoint) {
        endpointInput.value = status.endpoint;
    }
}

async function refreshStoredStatus() {
    const status = await chrome.runtime.sendMessage({ type: 'persona_status_request' }).catch(() => null);
    updateStatus(status);
}

function normalizeNativeHost(endpoint: string | undefined): string | undefined | null {
    if (!endpoint) return undefined;
    const trimmed = endpoint.trim();
    if (!trimmed) return undefined;
    if (trimmed.startsWith('native:')) return trimmed.slice('native:'.length);
    if (trimmed === 'native') return undefined;
    return null;
}

async function refreshPairing() {
    if (!pairingStatusEl) return;

    const host = normalizeNativeHost(endpointInput?.value);
    if (host === null) {
        pairingStatusEl.textContent = 'Pairing only works with native: endpoints';
        return;
    }
    const [state, helloResp] = await Promise.all([getPairingState(), hello(host)]);

    if (!helloResp?.ok) {
        pairingStatusEl.textContent = `Pairing unavailable – ${helloResp?.error ?? 'bridge not reachable'}`;
        return;
    }

    const pairingRequired = Boolean(helloResp.payload?.pairing_required);
    const paired = Boolean(state?.pairingKeyB64);

    if (paired) {
        pairingStatusEl.textContent = 'Paired (authenticated)';
    } else if (pairingRequired) {
        pairingStatusEl.textContent = 'Pairing required';
    } else {
        pairingStatusEl.textContent = 'Not paired';
    }
}

function renderForms(snapshot: any) {
    if (!formsContainer) return;
    if (!snapshot?.forms?.length) {
        formsContainer.textContent = 'No forms detected on the active tab yet.';
        return;
    }
    const lines = snapshot.forms
        .map((form: any) => {
            const fields = form.fields?.map((field: any) => field.type).join(', ');
            return `• [${form.method}] score ${form.score} – ${fields}`;
        })
        .join('\n');
    formsContainer.textContent = `Host: ${snapshot.host}\n${lines}`;
}

function renderDomainAssessment(assessment?: DomainAssessment) {
    const hostDisplay = currentHost ?? 'N/A';
    if (domainStatusEl) {
        if (!assessment) {
            domainStatusEl.textContent = `No domain data yet (host: ${hostDisplay})`;
        } else {
            domainStatusEl.textContent = `Host ${hostDisplay} → ${assessment.risk.toUpperCase()}`;
        }
    }
    if (domainReasonsEl) {
        if (!assessment?.reasons?.length) {
            domainReasonsEl.textContent = 'No heuristics triggered.';
        } else {
            domainReasonsEl.textContent = assessment.reasons.map((reason) => `• ${reason}`).join('\n');
        }
    }
    updatePolicyButtons();
}

function updatePolicyButtons() {
    const hasHost = Boolean(currentHost);
    const policy = currentAssessment?.policy;
    if (trustButton) {
        trustButton.toggleAttribute('disabled', !hasHost || currentAssessment?.risk === 'trusted');
    }
    if (blockButton) {
        blockButton.toggleAttribute('disabled', !hasHost || currentAssessment?.risk === 'blocked');
    }
    if (clearPolicyButton) {
        clearPolicyButton.toggleAttribute('disabled', !policy);
    }
}

async function refreshForms() {
    const snapshot = await chrome.runtime.sendMessage({ type: 'persona_forms_request' }).catch(() => null);
    currentHost = snapshot?.host;
    currentAssessment = snapshot?.assessment;
    renderForms(snapshot);
    renderDomainAssessment(snapshot?.assessment);
}

async function applyPolicy(trust: 'trusted' | 'blocked') {
    if (!currentHost) return;
    await chrome.runtime
        .sendMessage({
            type: 'persona_domain_trust',
            host: currentHost,
            trust
        })
        .catch(() => null);
    await refreshForms();
}

async function clearPolicy() {
    if (!currentHost) return;
    if (!currentAssessment?.policy) return;
    await chrome.runtime
        .sendMessage({
            type: 'persona_domain_remove',
            host: currentHost
        })
        .catch(() => null);
    await refreshForms();
}

if (toggleButton) {
    toggleButton.addEventListener('click', async () => {
        updateStatus({
            connected: false,
            endpoint: endpointInput?.value ?? '',
            lastChecked: Date.now(),
            message: 'Probing bridge...'
        } as BridgeStatus);
        const result = await chrome.runtime
            .sendMessage({
                type: 'persona_ping',
                endpoint: endpointInput?.value || undefined
            })
            .catch(() => null);
        updateStatus(result);
        await refreshPairing().catch(() => null);
    });
}

if (requestPairingButton) {
    requestPairingButton.addEventListener('click', async () => {
        const host = normalizeNativeHost(endpointInput?.value);
        if (host === null) {
            if (pairingHintEl) pairingHintEl.textContent = 'Set endpoint to native:com.persona.native first.';
            await refreshPairing().catch(() => null);
            return;
        }
        const resp = await requestPairingCode(host).catch((e) => ({ ok: false, error: String(e) }) as any);
        if (!resp?.ok) {
            if (pairingHintEl) pairingHintEl.textContent = `Pairing request failed: ${resp?.error ?? 'unknown error'}`;
            await refreshPairing().catch(() => null);
            return;
        }
        const code = (resp as any).payload?.code;
        const approval = (resp as any).payload?.approval_command;
        if (pairingCodeInput && code) pairingCodeInput.value = code;
        if (pairingHintEl) pairingHintEl.textContent = approval ?? 'Run `persona bridge --approve-code <CODE>` then click Finalize.';
        await refreshPairing().catch(() => null);
    });
}

if (finalizePairingButton) {
    finalizePairingButton.addEventListener('click', async () => {
        const code = pairingCodeInput?.value?.trim();
        if (!code) return;
        const host = normalizeNativeHost(endpointInput?.value);
        if (host === null) {
            if (pairingHintEl) pairingHintEl.textContent = 'Set endpoint to native:com.persona.native first.';
            await refreshPairing().catch(() => null);
            return;
        }
        const resp = await finalizePairing(code, host).catch((e) => ({ ok: false, error: String(e) }) as any);
        if (!resp?.ok) {
            if (pairingHintEl) pairingHintEl.textContent = `Finalize failed: ${resp?.error ?? 'unknown error'}`;
        } else {
            if (pairingHintEl) pairingHintEl.textContent = 'Paired successfully.';
        }
        await refreshPairing().catch(() => null);
    });
}

if (trustButton) {
    trustButton.addEventListener('click', () => applyPolicy('trusted'));
}

if (blockButton) {
    blockButton.addEventListener('click', () => applyPolicy('blocked'));
}

if (clearPolicyButton) {
    clearPolicyButton.addEventListener('click', () => clearPolicy());
}

document.addEventListener('DOMContentLoaded', () => {
    refreshStoredStatus();
    refreshForms();
    refreshPairing().catch(() => null);
    refreshAutofill().catch(() => null);
});

async function getActiveTabOrigin(): Promise<{ tabId: number; origin: string } | null> {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs?.[0];
    if (!tab?.id || !tab.url) return null;
    try {
        const url = new URL(tab.url);
        return { tabId: tab.id, origin: url.origin };
    } catch {
        return null;
    }
}

function renderSuggestions(items: any[], tabId: number) {
    if (!suggestionsEl) return;
    suggestionsEl.textContent = '';

    if (!items?.length) {
        const empty = document.createElement('div');
        empty.className = 'status';
        empty.textContent = 'No suggestions for this page.';
        suggestionsEl.appendChild(empty);
        return;
    }

    for (const item of items) {
        const kind = (item.credential_type ?? 'password') as string;
        const row = document.createElement('div');
        row.style.cssText =
            'border:1px solid #e5e7eb;border-radius:8px;padding:10px;display:flex;flex-direction:column;gap:6px;';

        const title = document.createElement('div');
        title.style.cssText = 'font-weight:600;color:#111827;';
        title.textContent = item.title ?? item.item_id;

        const meta = document.createElement('div');
        meta.style.cssText = 'font-size:12px;color:#6b7280;display:flex;justify-content:space-between;gap:8px;';
        meta.textContent = `${kind.toUpperCase()}${item.username_hint ? ` • ${item.username_hint}` : ''}`;

        const btn = document.createElement('button');
        btn.className = 'secondary';
        btn.textContent = kind === 'totp' ? 'Fill 2FA code' : 'Fill login';
        btn.addEventListener('click', async () => {
            const messageType = kind === 'totp' ? 'persona_popup_fill_totp' : 'persona_popup_fill_password';
            await chrome.tabs.sendMessage(tabId, { type: messageType, itemId: item.item_id }).catch(() => null);
        });

        row.appendChild(title);
        row.appendChild(meta);
        row.appendChild(btn);
        suggestionsEl.appendChild(row);
    }
}

async function refreshAutofill() {
    if (!autofillStatusEl) return;
    const active = await getActiveTabOrigin();
    if (!active) {
        autofillStatusEl.textContent = 'Open a normal web page to see suggestions.';
        return;
    }

    autofillStatusEl.textContent = `Origin: ${active.origin}`;

    const resp = await chrome.runtime
        .sendMessage({ type: 'persona_get_suggestions', origin: active.origin })
        .catch(() => null);

    if (!resp?.success) {
        autofillStatusEl.textContent = `Suggestions unavailable – ${resp?.error ?? 'bridge not connected'}`;
        renderSuggestions([], active.tabId);
        return;
    }

    const items = resp?.data?.items ?? resp?.data?.payload?.items ?? resp?.data?.items;
    renderSuggestions(items ?? [], active.tabId);
}
