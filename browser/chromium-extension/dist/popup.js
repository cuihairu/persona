import { hello, requestPairingCode, finalizePairing, getPairingState, generatePassword, accountLogin, accountStatus, accountLogout, syncPushNow } from './nativeBridge';
import { getAutofillSettings, setAutofillSettings } from './settings';
import { getAutofillDefaultsForOrigin, setAutofillDefaultsForOrigin } from './autofillDefaults';
import { connectViaBridge, loadCloudConn, saveCloudConn, saveCloudCache, pullCloudOps, buildItemViews, decryptItemViews, } from './cloudSync';
const statusEl = document.getElementById('status');
const toggleButton = document.getElementById('toggle');
const endpointInput = document.getElementById('endpoint');
const formsContainer = document.getElementById('forms');
const domainStatusEl = document.getElementById('domainStatus');
const domainReasonsEl = document.getElementById('domainReasons');
const trustButton = document.getElementById('trustDomain');
const blockButton = document.getElementById('blockDomain');
const clearPolicyButton = document.getElementById('clearDomainPolicy');
const pairingStatusEl = document.getElementById('pairingStatus');
const requestPairingButton = document.getElementById('requestPairing');
const pairingCodeInput = document.getElementById('pairingCode');
const pairingHintEl = document.getElementById('pairingHint');
const finalizePairingButton = document.getElementById('finalizePairing');
const autofillStatusEl = document.getElementById('autofillStatus');
const suggestionsEl = document.getElementById('suggestions');
const autoFillLoginOnFocusEl = document.getElementById('autoFillLoginOnFocus');
const autoFillLoginOnLoadEl = document.getElementById('autoFillLoginOnLoad');
const autoFillTotpOnFocusEl = document.getElementById('autoFillTotpOnFocus');
const autoFillTotpAfterLoginEl = document.getElementById('autoFillTotpAfterLogin');
const requireTrustedDomainEl = document.getElementById('requireTrustedDomain');
const savePromptEnabledEl = document.getElementById('savePromptEnabled');
const minMatchStrengthLoginEl = document.getElementById('minMatchStrengthLogin');
const minMatchStrengthTotpEl = document.getElementById('minMatchStrengthTotp');
let currentAssessment;
let currentHost;
function describeStatus(status) {
    if (!status)
        return 'Bridge unavailable';
    const ts = new Date(status.lastChecked).toLocaleTimeString();
    const base = status.connected ? 'Connected' : 'Disconnected';
    const connectInfo = status.payload?.connect_available
        ? ` • Desktop linked (port ${status.payload.connect_port})`
        : ' • Desktop not linked';
    const detail = status.message ? ` – ${status.message}` : '';
    return `${base}${connectInfo}${detail} (${ts})`;
}
function updateStatus(status) {
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
function normalizeNativeHost(endpoint) {
    if (!endpoint)
        return undefined;
    const trimmed = endpoint.trim();
    if (!trimmed)
        return undefined;
    if (trimmed.startsWith('native:'))
        return trimmed.slice('native:'.length);
    if (trimmed === 'native')
        return undefined;
    return null;
}
async function refreshPairing() {
    if (!pairingStatusEl)
        return;
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
    }
    else if (pairingRequired) {
        pairingStatusEl.textContent = 'Pairing required';
    }
    else {
        pairingStatusEl.textContent = 'Not paired';
    }
}
function renderForms(snapshot) {
    if (!formsContainer)
        return;
    if (!snapshot?.forms?.length) {
        formsContainer.textContent = 'No forms detected on the active tab yet.';
        return;
    }
    const lines = snapshot.forms
        .map((form) => {
        const fields = form.fields?.map((field) => field.type).join(', ');
        return `• [${form.method}] score ${form.score} – ${fields}`;
    })
        .join('\n');
    formsContainer.textContent = `Host: ${snapshot.host}\n${lines}`;
}
function renderDomainAssessment(assessment) {
    const hostDisplay = currentHost ?? 'N/A';
    if (domainStatusEl) {
        if (!assessment) {
            domainStatusEl.textContent = `No domain data yet (host: ${hostDisplay})`;
        }
        else {
            domainStatusEl.textContent = `Host ${hostDisplay} → ${assessment.risk.toUpperCase()}`;
        }
    }
    if (domainReasonsEl) {
        if (!assessment?.reasons?.length) {
            domainReasonsEl.textContent = 'No heuristics triggered.';
        }
        else {
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
async function applyPolicy(trust) {
    if (!currentHost)
        return;
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
    if (!currentHost)
        return;
    if (!currentAssessment?.policy)
        return;
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
        });
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
            if (pairingHintEl)
                pairingHintEl.textContent = 'Set endpoint to native:com.persona.native first.';
            await refreshPairing().catch(() => null);
            return;
        }
        const resp = await requestPairingCode(host).catch((e) => ({ ok: false, error: String(e) }));
        if (!resp?.ok) {
            if (pairingHintEl)
                pairingHintEl.textContent = `Pairing request failed: ${resp?.error ?? 'unknown error'}`;
            await refreshPairing().catch(() => null);
            return;
        }
        const code = resp.payload?.code;
        const approval = resp.payload?.approval_command;
        if (pairingCodeInput && code)
            pairingCodeInput.value = code;
        if (pairingHintEl)
            pairingHintEl.textContent = approval ?? 'Run `persona bridge --approve-code <CODE>` then click Finalize.';
        await refreshPairing().catch(() => null);
    });
}
if (finalizePairingButton) {
    finalizePairingButton.addEventListener('click', async () => {
        const code = pairingCodeInput?.value?.trim();
        if (!code)
            return;
        const host = normalizeNativeHost(endpointInput?.value);
        if (host === null) {
            if (pairingHintEl)
                pairingHintEl.textContent = 'Set endpoint to native:com.persona.native first.';
            await refreshPairing().catch(() => null);
            return;
        }
        const resp = await finalizePairing(code, host).catch((e) => ({ ok: false, error: String(e) }));
        if (!resp?.ok) {
            if (pairingHintEl)
                pairingHintEl.textContent = `Finalize failed: ${resp?.error ?? 'unknown error'}`;
        }
        else {
            if (pairingHintEl)
                pairingHintEl.textContent = 'Paired successfully.';
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
const genLengthEl = document.getElementById('genLength');
const genLowerEl = document.getElementById('genLower');
const genUpperEl = document.getElementById('genUpper');
const genDigitsEl = document.getElementById('genDigits');
const genSymbolsEl = document.getElementById('genSymbols');
const genPronounceableEl = document.getElementById('genPronounceable');
const genWordsEl = document.getElementById('genWords');
const genGenerateButton = document.getElementById('genGenerate');
const genResultEl = document.getElementById('genResult');
if (genGenerateButton) {
    genGenerateButton.addEventListener('click', async () => {
        if (!genResultEl)
            return;
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
        }).catch((e) => ({ ok: false, error: String(e) }));
        if (response?.ok && response.payload?.password) {
            genResultEl.textContent = response.payload.password;
        }
        else {
            genResultEl.textContent = `Error: ${response?.error ?? 'generation failed'}`;
        }
        genGenerateButton.toggleAttribute('disabled', false);
    });
}
// ============ Cloud vault (bridge protocol v6, M5 批1) ============
const cloudStatusEl = document.getElementById('cloudStatus');
const cloudConnectButton = document.getElementById('cloudConnect');
const cloudRefreshButton = document.getElementById('cloudRefresh');
const cloudPushButton = document.getElementById('cloudPush');
const cloudItemsEl = document.getElementById('cloudItems');
function cloudErrorText(error) {
    return error instanceof Error ? error.message : String(error);
}
function setCloudStatus(text) {
    if (cloudStatusEl)
        cloudStatusEl.textContent = text;
}
function setCloudConnected(conn) {
    cloudRefreshButton?.toggleAttribute('disabled', !conn);
    cloudPushButton?.toggleAttribute('disabled', !conn);
    setCloudStatus(conn ? `Connected • device ${conn.deviceName} • ${conn.serverUrl}` : 'Not connected');
}
function renderCloudItems(items) {
    if (!cloudItemsEl)
        return;
    cloudItemsEl.textContent = '';
    const live = items.filter((item) => !item.deleted);
    if (!live.length) {
        const empty = document.createElement('div');
        empty.className = 'status';
        empty.textContent = items.length ? 'All items deleted upstream.' : 'Vault is empty.';
        cloudItemsEl.appendChild(empty);
        return;
    }
    for (const item of live) {
        const row = document.createElement('div');
        row.style.cssText =
            'border:1px solid #e5e7eb;border-radius:8px;padding:10px;display:flex;flex-direction:column;gap:6px;';
        const title = document.createElement('div');
        title.style.cssText = 'font-weight:600;color:#111827;';
        title.textContent = item.meta?.name ?? item.item_id;
        const meta = document.createElement('div');
        meta.style.cssText = 'font-size:12px;color:#6b7280;';
        if (item.decrypt_error) {
            meta.textContent = `decrypt failed (${item.decrypt_error})`;
        }
        else if (item.meta) {
            const bits = [item.meta.credential_type, item.meta.security_level];
            if (item.meta.username)
                bits.push(item.meta.username);
            if (item.conflict_count > 0)
                bits.push(`${item.conflict_count} in conflict`);
            meta.textContent = bits.join(' • ');
        }
        else {
            meta.textContent = item.kind;
        }
        row.appendChild(title);
        row.appendChild(meta);
        cloudItemsEl.appendChild(row);
    }
}
async function pullAndRender(conn) {
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
        renderCloudItems(items);
        const live = items.filter((item) => !item.deleted).length;
        const conflicts = views.filter((view) => view.conflicts.length > 0).length;
        const parts = [`Connected • ${live} items`, `${pull.ops.length} ops`];
        if (conflicts > 0)
            parts.push(`${conflicts} in conflict (pending adjudication)`);
        setCloudStatus(parts.join(' • '));
    }
    catch (error) {
        // 拉取失败不掩盖既有连接状态；密文缓存仍在，离线兜底在后续批次接上
        setCloudStatus(`Pull failed – ${cloudErrorText(error)}`);
    }
}
cloudConnectButton?.addEventListener('click', async () => {
    cloudConnectButton.toggleAttribute('disabled', true);
    setCloudStatus('Connecting via local bridge…');
    try {
        const conn = await connectViaBridge();
        // best-effort 申请该 sync server 的 host 权限（用户点击上下文内）；
        // 拒绝也不拦——服务器若发 CORS，fetch 依然可用
        try {
            await chrome.permissions.request({ origins: [`${new URL(conn.serverUrl).origin}/*`] });
        }
        catch {
            // 权限 API 不可用/被拒：继续，拉取阶段如实报错
        }
        await saveCloudConn(conn);
        setCloudConnected(conn);
        await pullAndRender(conn);
    }
    catch (error) {
        setCloudStatus(`Connect failed – ${cloudErrorText(error)}`);
    }
    finally {
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
        if (r.backfilled > 0)
            parts.push(`backfilled ${r.backfilled}`);
        if (r.conflicts > 0)
            parts.push(`${r.conflicts} conflicts pending adjudication`);
        if (r.pending_identity > 0)
            parts.push(`${r.pending_identity} pending identity`);
        setCloudStatus(`Synced • ${parts.join(' • ')}`);
        // 推送改变了远端 oplog——顺手拉一次刷新列表
        const conn = await loadCloudConn();
        if (conn)
            await pullAndRender(conn);
    }
    finally {
        const conn = await loadCloudConn();
        cloudPushButton?.toggleAttribute('disabled', !conn);
    }
});
async function initCloudVault() {
    try {
        const conn = await loadCloudConn();
        setCloudConnected(conn);
        if (conn)
            await pullAndRender(conn);
    }
    catch {
        setCloudConnected(undefined);
    }
}
// ============ Account (bridge protocol v7, M5 批2) ============
const accountStatusEl = document.getElementById('accountStatus');
const accountIdInput = document.getElementById('accountId');
const accountPasswordInput = document.getElementById('accountPassword');
const accountLoginButton = document.getElementById('accountLoginBtn');
const accountLogoutButton = document.getElementById('accountLogoutBtn');
function setAccountStatus(text) {
    if (accountStatusEl)
        accountStatusEl.textContent = text;
}
async function refreshAccountStatus() {
    const resp = await accountStatus().catch((e) => ({ ok: false, error: String(e) }));
    if (!resp?.ok) {
        setAccountStatus(`Unavailable – ${resp?.error ?? 'bridge not reachable'}`);
        return;
    }
    const payload = resp.payload;
    if (!payload) {
        setAccountStatus('Unavailable – malformed response');
        return;
    }
    if (payload.has_session) {
        setAccountStatus('Signed in');
    }
    else if (payload.server_configured) {
        setAccountStatus('Not signed in');
    }
    else {
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
        const payload = resp.payload;
        setAccountStatus(`Signed in • token valid ${Math.round(payload.expires_in_secs / 60)} min • fingerprint ${payload.session_key_fingerprint.slice(0, 12)}…`);
        if (accountPasswordInput)
            accountPasswordInput.value = '';
    }
    finally {
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
        const payload = resp.payload;
        setAccountStatus(payload.revoked_on_server ? 'Signed out (session revoked)' : 'Signed out (local token cleared)');
    }
    finally {
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
async function getActiveTabOrigin() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs?.[0];
    if (!tab?.id || !tab.url)
        return null;
    try {
        const url = new URL(tab.url);
        return { tabId: tab.id, origin: url.origin };
    }
    catch {
        return null;
    }
}
function renderSuggestions(items, tabId, origin, defaults) {
    if (!suggestionsEl)
        return;
    suggestionsEl.textContent = '';
    if (!items?.length) {
        const empty = document.createElement('div');
        empty.className = 'status';
        empty.textContent = 'No suggestions for this page.';
        suggestionsEl.appendChild(empty);
        return;
    }
    for (const item of items) {
        const kind = (item.credential_type ?? 'password');
        if (kind === 'bank_card') {
            renderCardRow(item);
            continue;
        }
        const isDefault = kind === 'totp'
            ? defaults?.totpItemId === item.item_id
            : defaults?.passwordItemId === item.item_id;
        const row = document.createElement('div');
        row.style.cssText =
            'border:1px solid #e5e7eb;border-radius:8px;padding:10px;display:flex;flex-direction:column;gap:6px;';
        const title = document.createElement('div');
        title.style.cssText = 'font-weight:600;color:#111827;';
        title.textContent = `${item.title ?? item.item_id}${isDefault ? ' (Default)' : ''}`;
        const meta = document.createElement('div');
        meta.style.cssText = 'font-size:12px;color:#6b7280;display:flex;justify-content:space-between;gap:8px;';
        meta.textContent = `${kind.toUpperCase()} • match ${item.match_strength ?? '?'}${item.username_hint ? ` • ${item.username_hint}` : ''}`;
        const actions = document.createElement('div');
        actions.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;';
        const fillBtn = document.createElement('button');
        fillBtn.className = 'secondary';
        fillBtn.style.width = 'auto';
        fillBtn.textContent = kind === 'totp' ? 'Fill 2FA code' : 'Fill login';
        fillBtn.addEventListener('click', async () => {
            const messageType = kind === 'totp' ? 'persona_popup_fill_totp' : 'persona_popup_fill_password';
            await chrome.tabs.sendMessage(tabId, { type: messageType, itemId: item.item_id }).catch(() => null);
        });
        const copyBtn = document.createElement('button');
        copyBtn.className = 'secondary';
        copyBtn.style.width = 'auto';
        copyBtn.textContent = kind === 'totp' ? 'Copy 2FA code' : 'Copy password';
        copyBtn.addEventListener('click', async () => {
            const active = await getActiveTabOrigin();
            if (!active)
                return;
            await requestCopy(active.origin, item.item_id, kind === 'totp' ? 'totp' : 'password');
        });
        actions.appendChild(fillBtn);
        actions.appendChild(copyBtn);
        const defaultBtn = document.createElement('button');
        defaultBtn.className = 'secondary';
        defaultBtn.style.width = 'auto';
        defaultBtn.textContent = isDefault ? 'Clear default' : 'Set default';
        defaultBtn.addEventListener('click', async () => {
            const patch = kind === 'totp'
                ? { totpItemId: isDefault ? undefined : item.item_id }
                : { passwordItemId: isDefault ? undefined : item.item_id };
            await setAutofillDefaultsForOrigin(origin, patch).catch(() => null);
            await refreshAutofill().catch(() => null);
        });
        actions.appendChild(defaultBtn);
        if (kind !== 'totp' && item.username_hint) {
            const copyUserBtn = document.createElement('button');
            copyUserBtn.className = 'secondary';
            copyUserBtn.style.width = 'auto';
            copyUserBtn.textContent = 'Copy username';
            copyUserBtn.addEventListener('click', async () => {
                const active = await getActiveTabOrigin();
                if (!active)
                    return;
                await requestCopy(active.origin, item.item_id, 'username');
            });
            actions.appendChild(copyUserBtn);
        }
        row.appendChild(title);
        row.appendChild(meta);
        row.appendChild(actions);
        suggestionsEl.appendChild(row);
    }
}
/**
 * Bank-card suggestion row. Card filling is URL-independent (cards have no
 * canonical site), so actions are: fill the card on the page, or copy a
 * field — including CVV, which is copy-only by design (never filled).
 */
function renderCardRow(item) {
    if (!suggestionsEl)
        return;
    const row = document.createElement('div');
    row.style.cssText =
        'border:1px solid #e5e7eb;border-radius:8px;padding:10px;display:flex;flex-direction:column;gap:6px;';
    const title = document.createElement('div');
    title.style.cssText = 'font-weight:600;color:#111827;';
    title.textContent = item.title ?? item.item_id;
    const meta = document.createElement('div');
    meta.style.cssText = 'font-size:12px;color:#6b7280;display:flex;justify-content:space-between;gap:8px;';
    meta.textContent = `BANK CARD • match ${item.match_strength ?? '?'}`;
    const actions = document.createElement('div');
    actions.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;';
    const fillBtn = document.createElement('button');
    fillBtn.className = 'secondary';
    fillBtn.style.width = 'auto';
    fillBtn.textContent = 'Fill card';
    fillBtn.addEventListener('click', async () => {
        const active = await getActiveTabOrigin();
        if (!active)
            return;
        await chrome.tabs
            .sendMessage(active.tabId, { type: 'persona_popup_fill_card', itemId: item.item_id })
            .catch(() => null);
        window.close();
    });
    actions.appendChild(fillBtn);
    for (const [label, field] of [
        ['Copy number', 'card_number'],
        ['Copy expiry', 'expiry_date'],
        ['Copy CVV', 'cvv']
    ]) {
        const copyBtn = document.createElement('button');
        copyBtn.className = 'secondary';
        copyBtn.style.width = 'auto';
        copyBtn.textContent = label;
        copyBtn.addEventListener('click', async () => {
            const active = await getActiveTabOrigin();
            if (!active)
                return;
            await requestCopy(active.origin, item.item_id, field);
        });
        actions.appendChild(copyBtn);
    }
    row.appendChild(title);
    row.appendChild(meta);
    row.appendChild(actions);
    suggestionsEl.appendChild(row);
}
async function refreshAutofill() {
    if (!autofillStatusEl)
        return;
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
    const defaults = await getAutofillDefaultsForOrigin(active.origin).catch(() => null);
    renderSuggestions([...(items ?? []), ...cardItems], active.tabId, active.origin, defaults);
}
async function requestCopy(origin, itemId, field) {
    if (!autofillStatusEl)
        return;
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
function clampMatchStrength(value) {
    if (!Number.isFinite(value))
        return 90;
    return Math.max(0, Math.min(100, Math.round(value)));
}
async function refreshSettings() {
    const settings = await getAutofillSettings();
    if (autoFillLoginOnFocusEl)
        autoFillLoginOnFocusEl.checked = settings.autoFillLoginOnFocus;
    if (autoFillLoginOnLoadEl)
        autoFillLoginOnLoadEl.checked = settings.autoFillLoginOnLoad;
    if (autoFillTotpOnFocusEl)
        autoFillTotpOnFocusEl.checked = settings.autoFillTotpOnFocus;
    if (autoFillTotpAfterLoginEl)
        autoFillTotpAfterLoginEl.checked = settings.autoFillTotpAfterLogin;
    if (requireTrustedDomainEl)
        requireTrustedDomainEl.checked = settings.requireTrustedDomain;
    if (savePromptEnabledEl)
        savePromptEnabledEl.checked = settings.savePromptEnabled;
    if (minMatchStrengthLoginEl)
        minMatchStrengthLoginEl.value = String(settings.minMatchStrengthLogin);
    if (minMatchStrengthTotpEl)
        minMatchStrengthTotpEl.value = String(settings.minMatchStrengthTotp);
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
        <details style="margin-top: 16px;">
            <summary style="cursor: pointer; color: #6b7280; font-size: 13px;">Keyboard shortcuts</summary>
            <div style="margin-top: 8px; font-size: 12px; color: #6b7280; line-height: 1.8;">
                <div><kbd style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-family:monospace;">Ctrl+Shift+P</kbd> Toggle overlay</div>
                <div><kbd style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-family:monospace;">Ctrl+Shift+Y</kbd> Mini search (global)</div>
            </div>
        </details>
    `;
}
//# sourceMappingURL=popup.js.map