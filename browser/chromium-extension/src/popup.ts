import type { BridgeStatus } from './nativeBridge.js';
import type { DomainAssessment } from './domainPolicy.js';
import { hello, requestPairingCode, finalizePairing, getPairingState, generatePassword, accountLogin, accountStatus, accountLogout, syncPushNow, syncResolveConflict, getTotp } from './nativeBridge.js';
import { renderDetail, type DetailTarget, type CopyOutcome, type TotpPayload } from './popupDetail.js';
import { activatableRows, steppedIndex, isNavKey, type NavRow } from './popupNav.js';
import { KIND_FILTERS, countByFacts, rowVisible, type KindFilter, type RowFacts } from './popupFilter.js';
import { getAutofillSettings, setAutofillSettings } from './settings.js';
import { getAutofillDefaultsForOrigin, setAutofillDefaultsForOrigin, type OriginAutofillDefaults } from './autofillDefaults.js';
import { contextHintLine, suggestionMetaLine } from './autofillUx.js';
import {
    connectViaBridge,
    loadCloudConn,
    saveCloudConn,
    saveCloudCache,
    loadCloudCache,
    isUsableCache,
    pullCloudOps,
    buildItemViews,
    decryptItemViews,
    conflictCopyViews,
    type CloudConn,
    type CloudListItem,
    type CloudItemView,
} from './cloudSync.js';

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

const autoFillLoginOnFocusEl = document.getElementById('autoFillLoginOnFocus') as HTMLInputElement | null;
const autoFillLoginOnLoadEl = document.getElementById('autoFillLoginOnLoad') as HTMLInputElement | null;
const autoFillTotpOnFocusEl = document.getElementById('autoFillTotpOnFocus') as HTMLInputElement | null;
const autoFillTotpAfterLoginEl = document.getElementById('autoFillTotpAfterLogin') as HTMLInputElement | null;
const requireTrustedDomainEl = document.getElementById('requireTrustedDomain') as HTMLInputElement | null;
const savePromptEnabledEl = document.getElementById('savePromptEnabled') as HTMLInputElement | null;
const minMatchStrengthLoginEl = document.getElementById('minMatchStrengthLogin') as HTMLInputElement | null;
const minMatchStrengthTotpEl = document.getElementById('minMatchStrengthTotp') as HTMLInputElement | null;

let currentAssessment: DomainAssessment | undefined;
let currentHost: string | undefined;

const detailPaneEl = document.getElementById('detailPane');
let navList: (NavRow & { el: HTMLElement })[] = [];
let navIndex = -1;

function describeStatus(status?: BridgeStatus | null) {
    if (!status) return 'Bridge unavailable';
    const ts = new Date(status.lastChecked).toLocaleTimeString();
    const base = status.connected ? 'Connected' : 'Disconnected';
    const connectInfo = status.payload?.connect_available
        ? ` • Desktop linked (port ${status.payload.connect_port})`
        : ' • Desktop not linked';
    const detail = status.message ? ` – ${status.message}` : '';
    return `${base}${connectInfo}${detail} (${ts})`;
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

// ============ Password generator (bridge protocol v5) ============

const genLengthEl = document.getElementById('genLength') as HTMLInputElement | null;
const genLowerEl = document.getElementById('genLower') as HTMLInputElement | null;
const genUpperEl = document.getElementById('genUpper') as HTMLInputElement | null;
const genDigitsEl = document.getElementById('genDigits') as HTMLInputElement | null;
const genSymbolsEl = document.getElementById('genSymbols') as HTMLInputElement | null;
const genPronounceableEl = document.getElementById('genPronounceable') as HTMLInputElement | null;
const genWordsEl = document.getElementById('genWords') as HTMLInputElement | null;
const genGenerateButton = document.getElementById('genGenerate');
const genResultEl = document.getElementById('genResult');

if (genGenerateButton) {
    genGenerateButton.addEventListener('click', async () => {
        if (!genResultEl) return;
        genGenerateButton.toggleAttribute('disabled', true);
        genResultEl.textContent = 'Generating…';
        const wordsRaw = genWordsEl?.value?.trim();
        const words = wordsRaw ? Number.parseInt(wordsRaw, 10) : undefined;
        const response = await generatePassword({
            length: Number.parseInt(genLengthEl?.value ?? '16', 10),
            include_lowercase: genLowerEl?.checked ?? true,
            include_uppercase: genUpperEl?.checked ?? true,
            include_digits: genDigitsEl?.checked ?? true,
            include_symbols: genSymbolsEl?.checked ?? true,
            pronounceable: genPronounceableEl?.checked ?? false,
            words
        }).catch((e: unknown) => ({ ok: false, error: String(e) }) as any);
        if (response?.ok && response.payload?.password) {
            genResultEl.textContent = response.payload.password;
        } else {
            genResultEl.textContent = `Error: ${response?.error ?? 'generation failed'}`;
        }
        genGenerateButton.toggleAttribute('disabled', false);
    });
}

// ============ Cloud vault (bridge protocol v6, M5 batch 1) ============

const cloudStatusEl = document.getElementById('cloudStatus');
const cloudConnectButton = document.getElementById('cloudConnect') as HTMLButtonElement | null;
const cloudRefreshButton = document.getElementById('cloudRefresh') as HTMLButtonElement | null;
const cloudPushButton = document.getElementById('cloudPush') as HTMLButtonElement | null;
const cloudItemsEl = document.getElementById('cloudItems');
const kindBarEl = document.getElementById('kindBar');
const filterEmptyEl = document.getElementById('filterEmpty');

// ============ Vault kind filter (chips + combined search) ============
// Filter state is module-level so the chip bar and the search box both feed
// one combined pass (category AND text); rows carry their kind on data-kind.

let kindFilter: KindFilter = 'all';

const KIND_LABELS: Record<KindFilter, string> = {
    all: 'All items',
    favorite: 'Favorites',
    password: 'Logins',
    totp: '2FA',
    bank_card: 'Bank cards'
};

function refreshKindBar(rows: RowFacts[]): void {
    if (!kindBarEl) return;
    const counts = countByFacts(rows);
    kindBarEl.textContent = '';
    for (const filter of KIND_FILTERS) {
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.className = 'chip';
        chip.textContent = `${KIND_LABELS[filter]} (${counts[filter]})`;
        chip.setAttribute('aria-pressed', String(kindFilter === filter));
        chip.addEventListener('click', () => {
            kindFilter = filter;
            for (const other of kindBarEl.querySelectorAll('button')) {
                other.setAttribute('aria-pressed', String(other === chip));
            }
            applyVaultFilters();
        });
        kindBarEl.appendChild(chip);
    }
}

/** Combined category+text visibility for the vault list. Hides conflict
 * sub-rows together with their parent item; toggles the filter empty-state
 * hint when rows exist but the current filters match none. Returns the
 * number of rows left visible. */
function applyVaultFilters(): number {
    if (!cloudItemsEl) return 0;
    const query = searchInput?.value ?? '';
    let visible = 0;
    let rows = 0;
    let parentVisible = true;
    for (const child of Array.from(cloudItemsEl.children)) {
        const el = child as HTMLElement;
        if (el.classList.contains('item')) {
            rows += 1;
            const facts: RowFacts = { kind: el.dataset.kind, favorite: el.dataset.favorite === 'true' };
            parentVisible = rowVisible(facts, el.textContent ?? '', kindFilter, query);
            el.style.display = parentVisible ? '' : 'none';
            if (parentVisible) visible += 1;
        } else {
            // conflict copies ride along with their parent row
            el.style.display = parentVisible ? '' : 'none';
        }
    }
    const filtered = visible === 0 && rows > 0 && (kindFilter !== 'all' || query.trim() !== '');
    if (filterEmptyEl) filterEmptyEl.hidden = !filtered;
    return visible;
}

function vaultSection(): HTMLElement | null {
    return cloudItemsEl ? cloudItemsEl.closest('.card') : null;
}

function cloudErrorText(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

function setCloudStatus(text: string) {
    if (cloudStatusEl) cloudStatusEl.textContent = text;
}

function setCloudConnected(conn: CloudConn | undefined) {
    cloudRefreshButton?.toggleAttribute('disabled', !conn);
    cloudPushButton?.toggleAttribute('disabled', !conn);
    setCloudStatus(
        conn ? `Connected • device ${conn.deviceName} • ${conn.serverUrl}` : 'Not connected'
    );
}

/** Render the cloud item list. items[i] and views[i] correspond one to one (decryptItemViews is order-preserving).
 * Items with concurrent conflict copies expand in place to show each version, with a "Keep this version" resolve button per copy. */
async function renderCloudItems(items: CloudListItem[], views: CloudItemView[], conn: CloudConn) {
    if (!cloudItemsEl) return;
    cloudItemsEl.textContent = '';
    const live = items.filter((item) => !item.deleted);
    refreshKindBar(live.map((item) => ({ kind: item.meta?.credential_type ?? item.kind, favorite: item.meta?.is_favorite === true })));

    if (!live.length) {
        const empty = document.createElement('div');
        empty.className = 'empty';
        empty.textContent = items.length ? 'All items deleted upstream.' : 'Vault is empty.';
        cloudItemsEl.appendChild(empty);
        applyVaultFilters();
        return;
    }

    for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.deleted) continue;

        const row = document.createElement('div');
        row.className = 'item';
        row.dataset.action = 'detail';
        row.dataset.kind = item.meta?.credential_type ?? item.kind;
        row.dataset.favorite = String(item.meta?.is_favorite === true);

        const glyph = document.createElement('div');
        glyph.className = 'glyph';
        const kind = (item.meta?.credential_type ?? '').toLowerCase();
        glyph.textContent = kind.includes('totp') || kind.includes('otp') ? 'T' : kind.includes('card') ? 'C' : 'L';

        const meta = document.createElement('div');
        meta.className = 'meta';
        const t = document.createElement('div');
        t.className = 't';
        t.textContent = item.meta?.name ?? item.item_id;
        const s = document.createElement('div');
        s.className = 's';
        if (item.decrypt_error) {
            s.textContent = `decrypt failed (${item.decrypt_error})`;
        } else if (item.meta) {
            const bits = [item.meta.credential_type, item.meta.security_level];
            if (item.meta.username) bits.push(item.meta.username);
            if (item.conflict_count > 0) bits.push(`${item.conflict_count} in conflict`);
            s.textContent = bits.join(' • ');
        } else {
            s.textContent = item.kind;
        }
        meta.appendChild(t);
        meta.appendChild(s);

        const tail = document.createElement('div');
        tail.className = 'tail';
        if (item.meta?.is_favorite === true) {
            const star = document.createElement('span');
            star.className = 'fav-star';
            star.textContent = '★';
            star.title = 'Favorite';
            tail.appendChild(star);
        }
        const host = hostFromMeta(item.meta?.url);
        if (host) tail.appendChild(document.createTextNode(host));

        row.addEventListener('click', () => {
            cloudItemsEl.querySelectorAll('.item.selected').forEach((el) => el.classList.remove('selected'));
            row.classList.add('selected');
            void openVaultDetail(item);
        });

        row.appendChild(glyph);
        row.appendChild(meta);
        row.appendChild(tail);
        cloudItemsEl.appendChild(row);

        if (item.conflict_count > 0) {
            const copies = await conflictCopyViews(views[i], conn.groupKeyHex);
            for (const copy of copies) {
                const copyRow = document.createElement('div');
                copyRow.className = 'conflict';

                const label = document.createElement('span');
                const bits = [`↳ ${copy.meta?.name ?? copy.op_id}`, `device ${copy.device_id.slice(0, 8)}`];
                if (copy.deleted) bits.push('tombstone');
                if (copy.decrypt_error) bits.push(`decrypt failed (${copy.decrypt_error})`);
                label.textContent = bits.join(' • ');

                const keepBtn = document.createElement('button');
                keepBtn.className = 'action secondary';
                keepBtn.textContent = 'Keep this version';
                keepBtn.addEventListener('click', async () => {
                    keepBtn.toggleAttribute('disabled', true);
                    setCloudStatus('Resolving conflict via local bridge…');
                    try {
                        const resp = await syncResolveConflict(item.item_id, copy.op_id);
                        if (!resp?.ok) {
                            setCloudStatus(`Resolve failed – ${resp?.error ?? 'unknown error'}`);
                            return;
                        }
                        setCloudStatus('Conflict resolved • refreshing…');
                        await pullAndRender(conn);
                    } finally {
                        keepBtn.toggleAttribute('disabled', false);
                    }
                });

                copyRow.appendChild(label);
                copyRow.appendChild(keepBtn);
                cloudItemsEl.appendChild(copyRow);
            }
        }
    }

    applyVaultFilters();
}

// ---- item detail (right pane) ----

function originFromMeta(url?: string | null): string | undefined {
    if (!url) return undefined;
    try {
        return new URL(url).origin;
    } catch {
        return undefined;
    }
}

function hostFromMeta(url?: string | null): string {
    if (!url) return '';
    try {
        return new URL(url).host;
    } catch {
        return '';
    }
}

function buildVaultTarget(item: CloudListItem): DetailTarget {
    return {
        itemId: item.item_id,
        title: item.meta?.name ?? item.item_id,
        subtitle: item.meta?.username ?? undefined,
        credentialType: item.meta?.credential_type ?? item.kind,
        url: originFromMeta(item.meta?.url),
        source: 'vault'
    };
}

async function openVaultDetail(item: CloudListItem) {
    const target = buildVaultTarget(item);
    const active = await getActiveTabOrigin().catch(() => null);
    const kind = (target.credentialType ?? '').toLowerCase();
    const fill = active
        ? () => void fillFromDetail(item.item_id, kind.includes('totp') ? 'totp' : 'password')
        : undefined;
    showDetail(target, { fill, fillLabel: fill ? 'Fill on page' : undefined });
}

async function fillFromDetail(itemId: string, kind: 'password' | 'totp') {
    const active = await getActiveTabOrigin();
    if (!active) return;
    const type = kind === 'totp' ? 'persona_popup_fill_totp' : 'persona_popup_fill_password';
    await chrome.tabs.sendMessage(active.tabId, { type, itemId }).catch(() => null);
}

async function copyFromDetail(origin: string | undefined, itemId: string, field: 'username' | 'password' | 'totp'): Promise<CopyOutcome> {
    if (!origin) return { ok: false, error: 'no known origin for this item' };
    const resp = await chrome.runtime
        .sendMessage({ type: 'persona_copy', origin, itemId, field, userGesture: true })
        .catch(() => null);
    if (!resp?.success) return { ok: false, error: resp?.error ?? 'copy failed' };
    if (!resp?.data?.copied) return { ok: false, error: 'native side refused the copy' };
    return { ok: true, clearAfterSeconds: resp?.data?.clear_after_seconds };
}

async function loadTotpFor(origin: string | undefined, itemId: string): Promise<TotpPayload | { error: string }> {
    if (!origin) return { error: 'no known origin for this item' };
    const resp = await getTotp(origin, itemId, true).catch(() => null);
    if (!resp?.ok) return { error: resp?.error ?? 'bridge unavailable' };
    const payload = resp.payload as { code?: string; remaining_seconds?: number; period?: number } | undefined;
    if (!payload?.code) return { error: 'no 2FA secret stored for this item' };
    return {
        code: payload.code,
        remainingSeconds: payload.remaining_seconds ?? 30,
        period: payload.period ?? 30
    };
}

function showDetail(target: DetailTarget, opts?: { fill?: () => void; fillLabel?: string }) {
    if (!detailPaneEl) return;
    renderDetail(detailPaneEl, target, {
        copyField: (field) => copyFromDetail(target.url, target.itemId, field),
        loadTotp: () => loadTotpFor(target.url, target.itemId),
        fill: opts?.fill,
        fillLabel: opts?.fillLabel
    });
    setConsoleMode(false);
}

async function pullAndRender(conn: CloudConn) {
    try {
        setCloudStatus(`Pulling from ${conn.serverUrl}…`);
        const pull = await pullCloudOps(conn);
        await saveCloudCache({
            server_url: conn.serverUrl,
            ops: pull.ops,
            next_cursor: pull.next_cursor,
            synced_at: Date.now()
        });
        const views = buildItemViews(pull.ops);
        const items = await decryptItemViews(views, conn.groupKeyHex);
        await renderCloudItems(items, views, conn);
        const live = items.filter((item) => !item.deleted).length;
        const conflicts = views.filter((view) => view.conflicts.length > 0).length;
        const parts = [`Connected • ${live} items`, `${pull.ops.length} ops`];
        if (conflicts > 0) parts.push(`${conflicts} in conflict (pending adjudication)`);
        setCloudStatus(parts.join(' • '));
    } catch (error) {
        // Offline fallback (M5 batch 4a): the local ciphertext cache (chrome.storage.local) is still there —
        // re-decrypt and render, label the cache time honestly in the status line, never pose as live data
        const cache = await loadCloudCache().catch(() => undefined);
        if (isUsableCache(cache, conn) && cache) {
            const views = buildItemViews(cache.ops);
            const items = await decryptItemViews(views, conn.groupKeyHex);
            await renderCloudItems(items, views, conn);
            const live = items.filter((item) => !item.deleted).length;
            const ageMin = Math.max(0, Math.round((Date.now() - cache.synced_at) / 60000));
            setCloudStatus(
                `Offline – showing ${live} cached items from ${ageMin} min ago – pull failed: ${cloudErrorText(error)}`
            );
        } else {
            setCloudStatus(`Pull failed – ${cloudErrorText(error)}`);
        }
    }
}

cloudConnectButton?.addEventListener('click', async () => {
    cloudConnectButton.toggleAttribute('disabled', true);
    setCloudStatus('Connecting via local bridge…');
    try {
        const conn = await connectViaBridge();
        // best-effort: request host permission for the sync server (while inside the user-click context);
        // a refusal does not block us — if the server sends CORS, fetch still works
        try {
            await chrome.permissions.request({ origins: [`${new URL(conn.serverUrl).origin}/*`] });
        } catch {
            // permissions API unavailable or denied: carry on, the pull phase reports errors honestly
        }
        await saveCloudConn(conn);
        setCloudConnected(conn);
        await pullAndRender(conn);
    } catch (error) {
        setCloudStatus(`Connect failed – ${cloudErrorText(error)}`);
    } finally {
        cloudConnectButton.toggleAttribute('disabled', false);
    }
});

cloudRefreshButton?.addEventListener('click', async () => {
    const conn = await loadCloudConn();
    if (!conn) {
        setCloudStatus('Not connected — connect via local bridge first.');
        setCloudConnected(undefined);
        return;
    }
    await pullAndRender(conn);
});

cloudPushButton?.addEventListener('click', async () => {
    cloudPushButton?.toggleAttribute('disabled', true);
    setCloudStatus('Running sync cycle via local bridge…');
    try {
        const resp = await syncPushNow();
        if (!resp?.ok || !resp.payload) {
            setCloudStatus(`Sync failed – ${resp?.error ?? 'unknown error'}`);
            return;
        }
        const r = resp.payload;
        const parts = [
            `pushed ${r.pushed}`,
            `pulled ${r.pulled} (materialized ${r.materialized})`
        ];
        if (r.backfilled > 0) parts.push(`backfilled ${r.backfilled}`);
        if (r.conflicts > 0) parts.push(`${r.conflicts} conflicts pending adjudication`);
        if (r.pending_identity > 0) parts.push(`${r.pending_identity} pending identity`);
        setCloudStatus(`Synced • ${parts.join(' • ')}`);
        // the push changed the remote oplog — pull once more to refresh the list
        const conn = await loadCloudConn();
        if (conn) await pullAndRender(conn);
    } finally {
        const conn = await loadCloudConn();
        cloudPushButton?.toggleAttribute('disabled', !conn);
    }
});

async function initCloudVault() {
    try {
        const conn = await loadCloudConn();
        setCloudConnected(conn);
        if (conn) await pullAndRender(conn);
    } catch {
        setCloudConnected(undefined);
    }
}

// ============ Account (bridge protocol v7, M5 batch 2) ============

const accountStatusEl = document.getElementById('accountStatus');
const accountIdInput = document.getElementById('accountId') as HTMLInputElement | null;
const accountPasswordInput = document.getElementById('accountPassword') as HTMLInputElement | null;
const accountLoginButton = document.getElementById('accountLoginBtn') as HTMLButtonElement | null;
const accountLogoutButton = document.getElementById('accountLogoutBtn') as HTMLButtonElement | null;

function setAccountStatus(text: string) {
    if (accountStatusEl) accountStatusEl.textContent = text;
}

async function refreshAccountStatus() {
    const resp = await accountStatus().catch((e: unknown) => ({ ok: false, error: String(e) }) as any);
    if (!resp?.ok) {
        setAccountStatus(`Unavailable – ${resp?.error ?? 'bridge not reachable'}`);
        return;
    }
    const payload = resp.payload as { has_session: boolean; server_configured: boolean } | undefined;
    if (!payload) {
        setAccountStatus('Unavailable – malformed response');
        return;
    }
    if (payload.has_session) {
        setAccountStatus('Signed in');
    } else if (payload.server_configured) {
        setAccountStatus('Not signed in');
    } else {
        setAccountStatus('Not signed in (sync server not configured)');
    }
    if (accountLogoutButton) {
        accountLogoutButton.toggleAttribute('disabled', !payload.has_session);
    }
}

accountLoginButton?.addEventListener('click', async () => {
    const accountId = accountIdInput?.value?.trim();
    const password = accountPasswordInput?.value ?? '';
    if (!accountId || !password) {
        setAccountStatus('Account ID and password are required.');
        return;
    }
    accountLoginButton?.toggleAttribute('disabled', true);
    setAccountStatus('Signing in…');
    try {
        const resp = await accountLogin({
            account_id: accountId,
            password,
            device_name: 'browser-extension'
        });
        if (!resp?.ok) {
            setAccountStatus(`Sign-in failed – ${resp?.error ?? 'unknown error'}`);
            return;
        }
        const payload = resp.payload as { expires_in_secs: number; session_key_fingerprint: string };
        setAccountStatus(
            `Signed in • token valid ${Math.round(payload.expires_in_secs / 60)} min • fingerprint ${payload.session_key_fingerprint.slice(0, 12)}…`
        );
        if (accountPasswordInput) accountPasswordInput.value = '';
    } finally {
        accountLoginButton?.toggleAttribute('disabled', false);
        await refreshAccountStatus().catch(() => null);
    }
});

accountLogoutButton?.addEventListener('click', async () => {
    const accountId = accountIdInput?.value?.trim();
    if (!accountId) {
        setAccountStatus('Account ID is required to sign out.');
        return;
    }
    accountLogoutButton?.toggleAttribute('disabled', true);
    try {
        const resp = await accountLogout(accountId);
        if (!resp?.ok) {
            setAccountStatus(`Sign-out failed – ${resp?.error ?? 'unknown error'}`);
            return;
        }
        const payload = resp.payload as { revoked_on_server: boolean };
        setAccountStatus(
            payload.revoked_on_server ? 'Signed out (session revoked)' : 'Signed out (local token cleared)'
        );
    } finally {
        accountLogoutButton?.toggleAttribute('disabled', false);
        await refreshAccountStatus().catch(() => null);
    }
});

document.addEventListener('DOMContentLoaded', () => {
    refreshStoredStatus();
    refreshForms();
    refreshPairing().catch(() => null);
    refreshAutofill().catch(() => null);
    refreshSettings().catch(() => null);
    initCloudVault().catch(() => null);
    refreshAccountStatus().catch(() => null);
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

function renderSuggestions(
    items: any[],
    tabId: number,
    origin: string,
    defaults: OriginAutofillDefaults | null,
    context?: any
) {
    if (!suggestionsEl) return;
    suggestionsEl.textContent = '';

    // Stage 4: the bridge's identity-level context suggestion (advisory —
    // the ordering already reflects it; this just explains it).
    const hint = contextHintLine(context);
    if (hint) {
        const banner = document.createElement('div');
        banner.className = 'context-hint';
        banner.textContent = hint;
        suggestionsEl.appendChild(banner);
    }

    if (!items?.length) {
        const empty = document.createElement('div');
        empty.className = 'empty';
        empty.textContent = 'No suggestions for this page.';
        suggestionsEl.appendChild(empty);
        return;
    }

    for (const item of items) {
        const kind = (item.credential_type ?? 'password') as string;
        if (kind === 'bank_card') {
            renderCardRow(item);
            continue;
        }
        const isDefault =
            kind === 'totp'
                ? defaults?.totpItemId === item.item_id
                : defaults?.passwordItemId === item.item_id;

        const row = document.createElement('div');
        row.className = 'item';
        row.dataset.action = 'fill';
        row.dataset.kind = kind;

        const glyph = document.createElement('div');
        glyph.className = 'glyph';
        glyph.textContent = kind === 'totp' ? 'T' : 'L';

        const meta = document.createElement('div');
        meta.className = 'meta';
        const t = document.createElement('div');
        t.className = 't';
        t.textContent = `${item.title ?? item.item_id}${isDefault ? ' (Default)' : ''}`;
        const s = document.createElement('div');
        s.className = 's';
        s.textContent = suggestionMetaLine(item);
        meta.appendChild(t);
        meta.appendChild(s);

        const tail = document.createElement('div');
        tail.className = 'tail';

        const star = document.createElement('button');
        star.className = 'minibtn';
        star.textContent = isDefault ? '★' : '☆';
        star.title = isDefault ? 'Clear default for this site' : 'Set as default for this site';
        star.setAttribute('aria-pressed', String(isDefault));
        star.addEventListener('click', async (ev) => {
            ev.stopPropagation();
            const patch =
                kind === 'totp'
                    ? { totpItemId: isDefault ? undefined : item.item_id }
                    : { passwordItemId: isDefault ? undefined : item.item_id };
            await setAutofillDefaultsForOrigin(origin, patch as any).catch(() => null);
            await refreshAutofill().catch(() => null);
        });
        tail.appendChild(star);

        const copyBtn = document.createElement('button');
        copyBtn.className = 'minibtn';
        copyBtn.textContent = '⧉';
        copyBtn.title = kind === 'totp' ? 'Copy 2FA code' : 'Copy password';
        copyBtn.addEventListener('click', async (ev) => {
            ev.stopPropagation();
            const active = await getActiveTabOrigin();
            if (!active) return;
            await requestCopy(active.origin, item.item_id, kind === 'totp' ? 'totp' : 'password');
        });
        tail.appendChild(copyBtn);

        if (kind !== 'totp' && item.username_hint) {
            const copyUserBtn = document.createElement('button');
            copyUserBtn.className = 'minibtn';
            copyUserBtn.textContent = '@';
            copyUserBtn.title = 'Copy username';
            copyUserBtn.addEventListener('click', async (ev) => {
                ev.stopPropagation();
                const active = await getActiveTabOrigin();
                if (!active) return;
                await requestCopy(active.origin, item.item_id, 'username');
            });
            tail.appendChild(copyUserBtn);
        }

        row.addEventListener('click', async () => {
            const messageType = kind === 'totp' ? 'persona_popup_fill_totp' : 'persona_popup_fill_password';
            await chrome.tabs.sendMessage(tabId, { type: messageType, itemId: item.item_id }).catch(() => null);
        });

        row.appendChild(glyph);
        row.appendChild(meta);
        row.appendChild(tail);
        suggestionsEl.appendChild(row);
    }
}

/**
 * Bank-card suggestion row. Card filling is URL-independent (cards have no
 * canonical site), so actions are: fill the card on the page, or copy a
 * field — including CVV, which is copy-only by design (never filled).
 */
function renderCardRow(item: any) {
    if (!suggestionsEl) return;

    const row = document.createElement('div');
    row.className = 'item';
    row.dataset.action = 'fill';
    row.dataset.kind = 'bank_card';

    const glyph = document.createElement('div');
    glyph.className = 'glyph';
    glyph.textContent = 'C';

    const meta = document.createElement('div');
    meta.className = 'meta';
    const t = document.createElement('div');
    t.className = 't';
    t.textContent = item.title ?? item.item_id;
    const s = document.createElement('div');
    s.className = 's';
    s.textContent = suggestionMetaLine(item);
    meta.appendChild(t);
    meta.appendChild(s);

    const tail = document.createElement('div');
    tail.className = 'tail';
    // CVV is copy-only by design (never filled), so it stays a copy action.
    for (const [glyphText, field, label] of [
        ['#', 'card_number', 'Copy card number'],
        ['E', 'expiry_date', 'Copy expiry date'],
        ['✱', 'cvv', 'Copy CVV (copy-only, never filled)']
    ] as Array<[string, CopyField, string]>) {
        const copyBtn = document.createElement('button');
        copyBtn.className = 'minibtn';
        copyBtn.textContent = glyphText;
        copyBtn.title = label;
        copyBtn.addEventListener('click', async (ev) => {
            ev.stopPropagation();
            const active = await getActiveTabOrigin();
            if (!active) return;
            await requestCopy(active.origin, item.item_id, field);
        });
        tail.appendChild(copyBtn);
    }

    row.addEventListener('click', async () => {
        const active = await getActiveTabOrigin();
        if (!active) return;
        await chrome.tabs
            .sendMessage(active.tabId, { type: 'persona_popup_fill_card', itemId: item.item_id })
            .catch(() => null);
        window.close();
    });

    row.appendChild(glyph);
    row.appendChild(meta);
    row.appendChild(tail);
    suggestionsEl.appendChild(row);
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
        renderSuggestions([], active.tabId, active.origin, null);
        return;
    }

    // Card suggestions ride a second request (form_type=card): every active
    // bank card, independent of the page URL. Failures just drop the section.
    const cardResp = await chrome.runtime
        .sendMessage({ type: 'persona_get_suggestions', origin: active.origin, formType: 'card' })
        .catch(() => null);
    const cardItems = cardResp?.success ? cardResp?.data?.items ?? [] : [];

    const items = resp?.data?.items ?? resp?.data?.payload?.items ?? resp?.data?.items;
    const context = resp?.data?.context ?? resp?.data?.payload?.context ?? null;
    const defaults = await getAutofillDefaultsForOrigin(active.origin).catch(() => null);
    renderSuggestions([...(items ?? []), ...cardItems], active.tabId, active.origin, defaults, context);
}

type CopyField = 'password' | 'username' | 'totp' | 'card_number' | 'cardholder_name' | 'expiry_date' | 'cvv';

async function requestCopy(origin: string, itemId: string, field: CopyField) {
    if (!autofillStatusEl) return;
    autofillStatusEl.textContent = `Copying ${field}...`;
    const resp = await chrome.runtime
        .sendMessage({
            type: 'persona_copy',
            origin,
            itemId,
            field,
            userGesture: true
        })
        .catch(() => null);

    if (!resp?.success) {
        autofillStatusEl.textContent = `Copy failed – ${resp?.error ?? 'unknown error'}`;
        return;
    }

    const copied = Boolean(resp?.data?.copied);
    autofillStatusEl.textContent = copied ? `Copied ${field}` : `Copy failed`;
}

function clampMatchStrength(value: number): number {
    if (!Number.isFinite(value)) return 90;
    return Math.max(0, Math.min(100, Math.round(value)));
}

async function refreshSettings() {
    const settings = await getAutofillSettings();
    if (autoFillLoginOnFocusEl) autoFillLoginOnFocusEl.checked = settings.autoFillLoginOnFocus;
    if (autoFillLoginOnLoadEl) autoFillLoginOnLoadEl.checked = settings.autoFillLoginOnLoad;
    if (autoFillTotpOnFocusEl) autoFillTotpOnFocusEl.checked = settings.autoFillTotpOnFocus;
    if (autoFillTotpAfterLoginEl) autoFillTotpAfterLoginEl.checked = settings.autoFillTotpAfterLogin;
    if (requireTrustedDomainEl) requireTrustedDomainEl.checked = settings.requireTrustedDomain;
    if (savePromptEnabledEl) savePromptEnabledEl.checked = settings.savePromptEnabled;
    if (minMatchStrengthLoginEl) minMatchStrengthLoginEl.value = String(settings.minMatchStrengthLogin);
    if (minMatchStrengthTotpEl) minMatchStrengthTotpEl.value = String(settings.minMatchStrengthTotp);
}

function bindSettings() {
    autoFillLoginOnFocusEl?.addEventListener('change', () => {
        void setAutofillSettings({ autoFillLoginOnFocus: Boolean(autoFillLoginOnFocusEl.checked) });
    });
    autoFillLoginOnLoadEl?.addEventListener('change', () => {
        void setAutofillSettings({ autoFillLoginOnLoad: Boolean(autoFillLoginOnLoadEl.checked) });
    });
    autoFillTotpOnFocusEl?.addEventListener('change', () => {
        void setAutofillSettings({ autoFillTotpOnFocus: Boolean(autoFillTotpOnFocusEl.checked) });
    });
    autoFillTotpAfterLoginEl?.addEventListener('change', () => {
        void setAutofillSettings({
            autoFillTotpAfterLogin: Boolean(autoFillTotpAfterLoginEl.checked)
        });
    });
    requireTrustedDomainEl?.addEventListener('change', () => {
        void setAutofillSettings({ requireTrustedDomain: Boolean(requireTrustedDomainEl.checked) });
    });
    savePromptEnabledEl?.addEventListener('change', () => {
        void setAutofillSettings({ savePromptEnabled: Boolean(savePromptEnabledEl.checked) });
    });
    minMatchStrengthLoginEl?.addEventListener('change', () => {
        const raw = Number(minMatchStrengthLoginEl.value);
        void setAutofillSettings({ minMatchStrengthLogin: clampMatchStrength(raw) });
    });
    minMatchStrengthTotpEl?.addEventListener('change', () => {
        const raw = Number(minMatchStrengthTotpEl.value);
        void setAutofillSettings({ minMatchStrengthTotp: clampMatchStrength(raw) });
    });
}

bindSettings();

// Keyboard shortcuts hint
const shortcutsEl = document.getElementById('shortcuts');
if (shortcutsEl) {
    shortcutsEl.innerHTML = `
        <div class="tiny" style="line-height:1.9;">
            <div><kbd>Ctrl+Shift+P</kbd> Toggle overlay</div>
            <div><kbd>Ctrl+Shift+Y</kbd> Mini search (global)</div>
            <div><kbd>/</kbd> Focus search (popup)</div>
        </div>
    `;
}

// ============ Popup shell: theme, console pane, search filter ============
// Pure presentation-layer wiring on top of the operator logic above; every
// element it touches outside its own ids is optional and null-guarded.

const rootEl = document.documentElement;

function applyTheme(theme: 'light' | 'dark' | null): void {
    if (theme) rootEl.setAttribute('data-theme', theme);
    else rootEl.removeAttribute('data-theme');
}

const themeBtn = document.getElementById('themeBtn');

async function initTheme(): Promise<void> {
    try {
        const stored = await chrome.storage.local.get('popupTheme');
        const theme = stored.popupTheme as 'light' | 'dark' | undefined;
        if (theme === 'light' || theme === 'dark') applyTheme(theme);
        // no stored preference: leave the authored attribute (and the system
        // media query) in charge
    } catch {
        // storage unavailable: keep whatever the document already declares
    }
    themeBtn?.addEventListener('click', async () => {
        const current = rootEl.getAttribute('data-theme')
            ?? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
        const next = current === 'dark' ? 'light' : 'dark';
        applyTheme(next);
        try {
            await chrome.storage.local.set({ popupTheme: next });
        } catch {
            // storage unavailable (e.g. devtools preview): theme still applies for the session
        }
    });
}

void initTheme();

function setConsoleMode(on: boolean) {
    document.body.classList.toggle('mode-console', on);
    consoleBtn?.setAttribute('aria-pressed', on ? 'true' : 'false');
}

const consoleBtn = document.getElementById('consoleBtn');
consoleBtn?.addEventListener('click', () => {
    setConsoleMode(!document.body.classList.contains('mode-console'));
});

function collectNavRows() {
    const els = Array.from(document.querySelectorAll<HTMLElement>('.pane-left .item'));
    navList = els
        .filter((el) => el.getClientRects().length > 0)
        .map((el, i) => ({ key: String(i), visible: true, isFill: el.dataset.action === 'fill', el }));
}

function applyNavSelection() {
    for (const el of document.querySelectorAll<HTMLElement>('.pane-left .item.selected')) {
        el.classList.remove('selected');
    }
    const current = activatableRows(navList)[navIndex];
    if (current) {
        current.el.classList.add('selected');
        current.el.scrollIntoView({ block: 'nearest' });
    }
}

function clearNavSelection() {
    navIndex = -1;
    applyNavSelection();
}

const searchInput = document.getElementById('searchInput') as HTMLInputElement | null;
if (searchInput) {
    window.addEventListener('keydown', (e) => {
        const active = document.activeElement;
        const searchFocused = active === searchInput;
        const inText = active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement;

        if (e.key === '/' && !inText) {
            e.preventDefault();
            searchInput.focus();
            return;
        }
        // arrows/enter/esc stay out of the way while typing in form inputs
        if (inText && !searchFocused) return;
        if (!isNavKey(e.key)) return;

        if (e.key === 'Escape') {
            if (document.body.classList.contains('mode-console')) {
                setConsoleMode(false);
                return;
            }
            if (navIndex >= 0) {
                clearNavSelection();
                return;
            }
            if (searchInput.value) {
                searchInput.value = '';
                searchInput.dispatchEvent(new Event('input'));
                return;
            }
            searchInput.blur();
            return;
        }

        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault();
            collectNavRows();
            const visible = activatableRows(navList);
            navIndex = steppedIndex(visible.length, navIndex, e.key === 'ArrowDown' ? 1 : -1);
            applyNavSelection();
            return;
        }

        // Enter activates the selected row; with nothing selected it takes
        // the first visible row (the top suggestion when searching).
        e.preventDefault();
        collectNavRows();
        const visible = activatableRows(navList);
        if (!visible.length) return;
        if (navIndex < 0 || navIndex >= visible.length) {
            navIndex = steppedIndex(visible.length, navIndex, 1);
        }
        const target = visible[navIndex];
        if (target) {
            target.el.classList.add('selected');
            target.el.click();
        }
    });

    const sections = Array.from(document.querySelectorAll<HTMLElement>('.pane-left .card'));
    const vaultCard = vaultSection();
    const otherSections = sections.filter((section) => section !== vaultCard);
    searchInput.addEventListener('input', () => {
        const q = searchInput.value.trim().toLowerCase();
        for (const section of otherSections) {
            const items = Array.from(section.querySelectorAll<HTMLElement>('.item'));
            const controls = Array.from(section.querySelectorAll<HTMLElement>('button, input, .gen-result'));
            const textMatch = (el: HTMLElement) => (el.textContent ?? '').toLowerCase().includes(q);
            let visible = true;
            if (q) {
                const itemsVisible = items.filter(textMatch);
                const controlsVisible = controls.filter(textMatch);
                visible = itemsVisible.length > 0 || controlsVisible.length > 0
                    || textMatch(section);
                items.forEach((it) => { it.style.display = itemsVisible.includes(it) ? '' : 'none'; });
            } else {
                items.forEach((it) => { it.style.display = ''; });
            }
            section.style.display = visible ? '' : 'none';
        }
        // vault card rides the combined kind+text filter; it stays visible
        // without a query even when a kind chip matches nothing (the
        // filter empty-state hint takes over)
        const vaultVisible = applyVaultFilters();
        if (vaultCard) {
            vaultCard.style.display = vaultVisible > 0 || !q ? '' : 'none';
        }
    });

    refreshKindBar([]);
    applyVaultFilters();
}
