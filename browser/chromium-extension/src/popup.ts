import type { BridgeStatus } from './bridge';
import type { DomainAssessment } from './domainPolicy';

const statusEl = document.getElementById('status');
const toggleButton = document.getElementById('toggle');
const endpointInput = document.getElementById('endpoint') as HTMLInputElement | null;
const formsContainer = document.getElementById('forms');
const domainStatusEl = document.getElementById('domainStatus');
const domainReasonsEl = document.getElementById('domainReasons');
const trustButton = document.getElementById('trustDomain');
const blockButton = document.getElementById('blockDomain');
const clearPolicyButton = document.getElementById('clearDomainPolicy');

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
});
