import { pingBridge, type BridgeStatus } from './bridge';
import {
    evaluateDomain,
    upsertPolicy,
    removePolicy,
    type DomainPolicy,
    type DomainAssessment
} from './domainPolicy';

const STORAGE_KEY = 'persona_bridge_status';
const FORMS_KEY = 'persona_forms';
const POLICY_KEY = 'persona_domain_policies';

chrome.runtime.onInstalled.addListener(() => {
    console.log('Persona extension installed');
    // Seed status so the popup can show something before the first button click.
    chrome.storage.local.set({
        [STORAGE_KEY]: {
            connected: false,
            endpoint: undefined,
            lastChecked: Date.now(),
            message: 'Bridge not contacted yet'
        },
        [POLICY_KEY]: []
    });
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === 'persona_ping') {
        handleBridgePing(message?.endpoint).then(sendResponse);
        return true; // keep channel open for async response
    }

    if (message?.type === 'persona_status_request') {
        chrome.storage.local.get(STORAGE_KEY, (value) => {
            sendResponse(value?.[STORAGE_KEY]);
        });
        return true;
    }

    if (message?.type === 'persona_forms_snapshot') {
        void updateFormsSnapshot(message.host, message.forms);
        return false;
    }

    if (message?.type === 'persona_forms_request') {
        chrome.storage.local.get(FORMS_KEY, (value) => {
            sendResponse(value?.[FORMS_KEY]);
        });
        return true;
    }

    if (message?.type === 'persona_domain_policies_get') {
        getPolicies().then((policies) => sendResponse(policies));
        return true;
    }

    if (message?.type === 'persona_domain_trust') {
        handlePolicyUpdate(message.host, message.trust, message.note).then((policies) => sendResponse(policies));
        return true;
    }

    if (message?.type === 'persona_domain_remove') {
        handlePolicyRemoval(message.host).then((policies) => sendResponse(policies));
        return true;
    }

    return false;
});

async function handleBridgePing(endpoint?: string): Promise<BridgeStatus> {
    const status = await pingBridge(endpoint);
    await chrome.storage.local.set({ [STORAGE_KEY]: status });
    await broadcastStatus(status);
    return status;
}

async function broadcastStatus(status: BridgeStatus) {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    for (const tab of tabs) {
        if (!tab.id) continue;
        chrome.tabs
            .sendMessage(tab.id, { type: 'persona_status', status })
            .catch(() => {
                /* Ignore tabs without the content script */
            });
    }
}

chrome.action.onClicked.addListener(async () => {
    await handleBridgePing();
});

async function getPolicies(): Promise<DomainPolicy[]> {
    return new Promise((resolve) => {
        chrome.storage.local.get(POLICY_KEY, (value) => resolve(value?.[POLICY_KEY] ?? []));
    });
}

async function setPolicies(policies: DomainPolicy[]): Promise<void> {
    return new Promise((resolve) => {
        chrome.storage.local.set({ [POLICY_KEY]: policies }, () => resolve());
    });
}

async function getFormsSnapshot(): Promise<
    | {
          host: string;
          forms: unknown[];
          capturedAt: number;
          assessment?: DomainAssessment;
      }
    | undefined
> {
    return new Promise((resolve) => {
        chrome.storage.local.get(FORMS_KEY, (value) => resolve(value?.[FORMS_KEY]));
    });
}

async function updateFormsSnapshot(host: string, forms: unknown[]) {
    const policies = await getPolicies();
    const assessment = evaluateDomain(host, policies);
    const payload = {
        host,
        forms,
        capturedAt: Date.now(),
        assessment
    };
    await chrome.storage.local.set({ [FORMS_KEY]: payload });
}

async function refreshAssessment() {
    const [snapshot, policies] = await Promise.all([getFormsSnapshot(), getPolicies()]);
    if (!snapshot?.host) return;
    const assessment = evaluateDomain(snapshot.host, policies);
    await chrome.storage.local.set({ [FORMS_KEY]: { ...snapshot, assessment } });
}

async function handlePolicyUpdate(host: string, trust: 'trusted' | 'blocked', note?: string) {
    const policies = await getPolicies();
    const next = upsertPolicy(policies, {
        host,
        trust,
        note,
        updatedAt: Date.now()
    });
    await setPolicies(next);
    await refreshAssessment();
    return next;
}

async function handlePolicyRemoval(host: string) {
    const policies = await getPolicies();
    const next = removePolicy(policies, host);
    await setPolicies(next);
    await refreshAssessment();
    return next;
}
