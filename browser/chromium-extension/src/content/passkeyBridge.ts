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


// ============ Passkey selection/confirm UI (bridge protocol v2) ============
//
// The MAIN-world hook (webauthnHook.ts) intercepts navigator.credentials and
// asks this ISOLATED-world script to run the confirmation UI and the bridge
// round-trip. Design rules (docs/PASSKEYS_DESIGN.md §8.2):
//   - create: explicit confirm dialog before any bridge request
//   - assert: candidate picker; no candidates -> no dialog, no request;
//     a single candidate still requires an explicit click (no silent signing)

export const PAGE_MESSAGE_SOURCE = 'persona-webauthn';
export const CONTENT_MESSAGE_SOURCE = 'persona-webauthn-content';


export function handlePasskeyPageMessage(event: MessageEvent) {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== PAGE_MESSAGE_SOURCE) return;

    if (data.type === 'PERSONA_PASSKEY_CANCEL') {
        // The page aborted the ceremony — drop the dialog if it's still up.
        if (state.passkeyOverlayRequestId === data.requestId) hidePasskeyOverlay();
        return;
    }

    if (data.type === 'PERSONA_PASSKEY_CREATE') {
        // Drop forged-origin requests before they reach the dialog/native gate.
        if (!isTrustedPasskeyOrigin(data.payload?.origin, location.origin)) return;
        void handlePasskeyCreateRequest(data.requestId, data.payload);
        return;
    }

    if (data.type === 'PERSONA_PASSKEY_GET') {
        // Same origin binding for the assertion/list path.
        if (!isTrustedPasskeyOrigin(data.payload?.origin, location.origin)) return;
        void handlePasskeyGetRequest(data.requestId, data.payload);
        return;
    }
}

export function replyToPage(requestId: string, message: Record<string, unknown>) {
    window.postMessage(
        { source: CONTENT_MESSAGE_SOURCE, requestId, ...message },
        location.origin
    );
}

export function fallbackToPage(requestId: string) {
    hidePasskeyOverlay();
    replyToPage(requestId, { type: 'PERSONA_PASSKEY_FALLBACK' });
}

export function handlePasskeyCreateRequest(requestId: string, payload: any) {
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

export async function handlePasskeyGetRequest(requestId: string, payload: any) {
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

export function hidePasskeyOverlay() {
    state.passkeyOverlay?.remove();
    state.passkeyOverlay = null;
    state.passkeyOverlayRequestId = null;
}

export function showPasskeyDialog(dialog: {
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
    state.passkeyOverlayRequestId = null;

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
    state.passkeyOverlay = backdrop;
}

// ---------------------------------------------------------------------------
// Save/update bar (bridge protocol v4). Capture points: real `submit` events
// plus clicks on submit-ish buttons (SPA logins often have no <form>). The
// proposal only ever becomes a vault write after an explicit bar click — the
// host refuses silent saves (`user_gesture_required`).
// ---------------------------------------------------------------------------

