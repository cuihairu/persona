/**
 * Right-pane item detail: field rows with copy actions and a live 2FA code.
 *
 * Zero-knowledge layout: secret values never reach the extension, so the
 * password row shows a masked placeholder whose only action is "Copy" —
 * the native side copies and clears the clipboard on its own timer
 * (clear_after_seconds). The 2FA row lazily loads a live code and keeps a
 * countdown ticking against its period, refreshing at expiry.
 *
 * All side effects arrive through DetailActions so tests can stub them.
 */

export interface DetailTarget {
    itemId: string;
    title: string;
    /** username hint / url shown under the title */
    subtitle?: string;
    credentialType?: string;
    /** origin the native bridge should scope copy/fill calls to */
    url?: string;
    source: 'vault' | 'suggestion';
}

export interface CopyOutcome {
    ok: boolean;
    clearAfterSeconds?: number;
    error?: string;
}

export interface TotpPayload {
    code: string;
    remainingSeconds: number;
    period: number;
}

export interface DetailActions {
    copyField(field: 'username' | 'password' | 'totp'): Promise<CopyOutcome>;
    loadTotp(): Promise<TotpPayload | { error: string }>;
    /** fill the active page tab; label overrides the default button text */
    fill?: () => void;
    fillLabel?: string;
}

let totpTimer: ReturnType<typeof setInterval> | null = null;
let totpToken = 0;
let clearNoteTimer: ReturnType<typeof setInterval> | null = null;
let clearNoteToken = 0;

/** Stop every detail-pane timer (live code + clipboard countdown) and
 * invalidate any in-flight loads. Call before re-render or teardown. */
export function clearTotpTicker(): void {
    if (totpTimer !== null) {
        clearInterval(totpTimer);
        totpTimer = null;
    }
    totpToken++;
    stopClearNote();
}

/** Group a code for reading: 123 456 / 1234 5678. */
export function groupCode(code: string): string {
    const clean = code.replace(/\s+/g, '');
    if (clean.length <= 4) return clean;
    if (clean.length === 8) return `${clean.slice(0, 4)} ${clean.slice(4)}`;
    const groups: string[] = [];
    for (let i = 0; i < clean.length; i += 3) groups.push(clean.slice(i, i + 3));
    // fold a trailing 1-2 char group into the previous one
    if (groups.length > 1 && groups[groups.length - 1].length < 3) {
        const last = groups.pop() as string;
        groups[groups.length - 1] += last;
    }
    return groups.join(' ');
}

type Role = 'username' | 'password' | 'totp';

export function renderDetail(root: HTMLElement, target: DetailTarget, actions: DetailActions): void {
    clearTotpTicker();
    stopClearNote();
    root.textContent = '';

    const empty = document.createElement('div');
    empty.className = 'detail-empty';
    empty.hidden = true;
    root.appendChild(empty);

    const body = document.createElement('div');
    body.className = 'detail-body';
    root.appendChild(body);

    // header: glyph, title/subtitle, type chip
    const head = document.createElement('div');
    head.className = 'detail-head';

    const glyph = document.createElement('div');
    glyph.className = 'glyph';
    glyph.textContent = glyphFor(target);
    head.appendChild(glyph);

    const headMeta = document.createElement('div');
    headMeta.className = 'meta';
    const t = document.createElement('div');
    t.className = 't';
    t.textContent = target.title;
    headMeta.appendChild(t);
    if (target.subtitle) {
        const s = document.createElement('div');
        s.className = 's';
        s.textContent = target.subtitle;
        headMeta.appendChild(s);
    }
    head.appendChild(headMeta);

    if (target.credentialType) {
        const chip = document.createElement('span');
        chip.className = 'chip';
        chip.textContent = target.credentialType;
        head.appendChild(chip);
    }
    body.appendChild(head);

    const rows = document.createElement('div');
    rows.className = 'detail-rows';

    appendFieldRow(rows, 'Username', target.subtitle ?? '—', target.subtitle ? 'username' : null, actions, body);
    appendFieldRow(rows, 'Password', '••••••••', 'password', actions, body);
    appendTotpRow(rows, target, actions);

    body.appendChild(rows);

    if (actions.fill) {
        const fillBtn = document.createElement('button');
        fillBtn.className = 'action';
        fillBtn.textContent = actions.fillLabel ?? 'Fill on page';
        fillBtn.addEventListener('click', () => actions.fill?.());
        body.appendChild(fillBtn);
    }

    const status = document.createElement('div');
    status.className = 'detail-status';
    status.dataset.role = 'status';
    body.appendChild(status);

    const note = document.createElement('div');
    note.className = 'detail-note';
    note.textContent = 'Secrets stay in the native app — copies auto-clear.';
    body.appendChild(note);

    const hints = document.createElement('div');
    hints.className = 'detail-hints';
    for (const [key, label] of [
        ['↑↓', 'Navigate'],
        ['Enter', 'Fill / open'],
        ['Esc', 'Back'],
        ['/', 'Search']
    ]) {
        const line = document.createElement('span');
        const k = document.createElement('kbd');
        k.textContent = key;
        line.appendChild(k);
        line.appendChild(document.createTextNode(label));
        hints.appendChild(line);
    }
    body.appendChild(hints);
}

function appendFieldRow(
    rows: HTMLElement,
    label: string,
    value: string,
    role: Role | null,
    actions: DetailActions,
    body: HTMLElement
): void {
    const row = document.createElement('div');
    row.className = 'drow';

    const lab = document.createElement('div');
    lab.className = 'dlabel';
    lab.textContent = label;
    row.appendChild(lab);

    const val = document.createElement('div');
    val.className = 'dvalue';
    if (role === 'password') val.classList.add('dots');
    val.textContent = value;
    val.title = role === 'password' ? 'Hidden — copy instead (auto-clears)' : value;
    row.appendChild(val);

    if (role) {
        const btn = document.createElement('button');
        btn.className = 'action secondary';
        btn.textContent = 'Copy';
        btn.addEventListener('click', () => {
            void doCopy(role, actions, body);
        });
        row.appendChild(btn);
    }
    rows.appendChild(row);
}

function appendTotpRow(rows: HTMLElement, target: DetailTarget, actions: DetailActions): void {
    const row = document.createElement('div');
    row.className = 'drow';

    const lab = document.createElement('div');
    lab.className = 'dlabel';
    lab.textContent = '2FA';
    row.appendChild(lab);

    const val = document.createElement('div');
    val.className = 'dvalue totp';
    val.dataset.role = 'totp-slot';
    val.textContent = '—';
    row.appendChild(val);

    const btn = document.createElement('button');
    btn.className = 'action secondary';
    btn.textContent = 'Show code';
    btn.dataset.role = 'totp-load';
    btn.addEventListener('click', () => {
        void loadTotpInto(val, actions);
        btn.disabled = true;
    });
    row.appendChild(btn);
    rows.appendChild(row);
}

async function loadTotpInto(slot: HTMLElement, actions: DetailActions): Promise<void> {
    const myToken = totpToken;
    const res = await actions.loadTotp();
    if (myToken !== totpToken) return; // superseded by another render
    if ('error' in res) {
        slot.textContent = 'unavailable';
        announce(slot, `2FA unavailable – ${res.error}`, true);
        return;
    }
    slot.textContent = groupCode(res.code);

    const bar = document.createElement('div');
    bar.className = 'totp-bar';
    const fill = document.createElement('div');
    fill.className = 'totp-fill';
    bar.appendChild(fill);
    const parent = slot.parentElement;
    if (parent) parent.appendChild(bar);

    let remaining = res.remainingSeconds;
    const period = res.period;
    const paint = () => {
        fill.style.width = `${Math.max(0, Math.min(100, (remaining / period) * 100))}%`;
        announce(slot, `2FA code shown · ${remaining}s left`, false);
    };
    paint();

    // one ticker per detail view: at expiry it refetches IN PLACE and the
    // same interval keeps ticking with the fresh window
    if (totpTimer !== null) clearInterval(totpTimer);
    totpTimer = setInterval(() => {
        remaining--;
        if (remaining <= 0) {
            void (async () => {
                const fresh = await actions.loadTotp();
                if (myToken !== totpToken) return;
                if ('error' in fresh) {
                    announce(slot, `2FA refresh failed – ${fresh.error}`, true);
                    return;
                }
                slot.textContent = groupCode(fresh.code);
                remaining = fresh.remainingSeconds;
                paint();
            })();
            return;
        }
        paint();
    }, 1000);
}

async function doCopy(role: Role, actions: DetailActions, body: HTMLElement): Promise<void> {
    const res = await actions.copyField(role);
    if (!res.ok) {
        announce(body, `Copy failed – ${res.error ?? 'unknown error'}`, true);
        return;
    }
    if (res.clearAfterSeconds && res.clearAfterSeconds > 0) {
        startClearNote(res.clearAfterSeconds, body);
    } else {
        stopClearNote();
        announce(body, `Copied ${role}`, false);
    }
}

/** Copy feedback with a visible countdown while the clipboard holds the secret. */
function startClearNote(seconds: number, body: HTMLElement): void {
    stopClearNote();
    const myToken = clearNoteToken;
    let left = seconds;
    const paint = () => announce(body, `Copied · clipboard clears in ${left}s`, false);
    paint();
    clearNoteTimer = setInterval(() => {
        if (myToken !== clearNoteToken) return;
        left--;
        if (left <= 0) {
            stopClearNote();
            announce(body, 'Clipboard cleared', false);
            return;
        }
        paint();
    }, 1000);
}

function stopClearNote(): void {
    if (clearNoteTimer !== null) {
        clearInterval(clearNoteTimer);
        clearNoteTimer = null;
    }
    clearNoteToken++;
}

function announce(scope: HTMLElement, message: string, isError: boolean): void {
    const root = scope.closest('.detail-body') ?? scope;
    const status = root.querySelector<HTMLElement>('[data-role="status"]');
    if (!status) return;
    status.textContent = message;
    status.classList.toggle('err', isError);
}

function glyphFor(target: DetailTarget): string {
    const type = (target.credentialType ?? '').toLowerCase();
    if (type.includes('totp') || type.includes('otp')) return 'T';
    if (type.includes('card')) return 'C';
    return 'L';
}
