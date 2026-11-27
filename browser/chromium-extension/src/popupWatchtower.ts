/**
 * Watchtower card: the popup face of the vault health scan. Three count
 * chips (weak / reused / no 2FA) summarize the report; expanding reveals
 * the hit rows, each one an .item that opens the item's detail pane.
 *
 * The report is metadata-only by protocol — item ids, names and issue
 * facts, never secret material — so rendering it is safe at any trust
 * level. All strings ride chrome.i18n; all side effects arrive through
 * the onOpen callback so tests can stub them.
 */

export interface WatchtowerIssue {
    item_id: string;
    name: string;
    severity: 'high' | 'medium' | 'low';
    detail: string;
    score?: number;
    group_size?: number;
    site?: string;
    days?: number;
}

export interface WatchtowerReport {
    scanned_at: string;
    total_credentials: number;
    weak: WatchtowerIssue[];
    reused: WatchtowerIssue[];
    no_totp: WatchtowerIssue[];
    stale: WatchtowerIssue[];
}

export interface WatchtowerActions {
    /** a hit row was clicked — open that item in the detail pane */
    onOpen(issue: WatchtowerIssue): void;
}

type Bucket = 'weak' | 'reused' | 'no_totp' | 'stale';

interface BucketSpec {
    key: Bucket;
    labelKey: string;
    glyph: string;
}

const BUCKETS: BucketSpec[] = [
    { key: 'weak', labelKey: 'popupWatchtowerWeak', glyph: 'W' },
    { key: 'reused', labelKey: 'popupWatchtowerReused', glyph: 'R' },
    { key: 'no_totp', labelKey: 'popupWatchtowerNoTotp', glyph: '2' },
    { key: 'stale', labelKey: 'popupWatchtowerStale', glyph: 'S' }
];

function msg(key: string): string {
    try {
        return chrome.i18n.getMessage(key) || '';
    } catch {
        return '';
    }
}

/** Merge the buckets into display rows, weakest severity first. */
export function watchtowerRows(report: WatchtowerReport): Array<{ issue: WatchtowerIssue; bucket: BucketSpec }> {
    const rows: Array<{ issue: WatchtowerIssue; bucket: BucketSpec }> = [];
    for (const bucket of BUCKETS) {
        for (const issue of report[bucket.key]) {
            rows.push({ issue, bucket });
        }
    }
    const weight = { high: 0, medium: 1, low: 2 } as const;
    rows.sort((a, b) => weight[a.issue.severity] - weight[b.issue.severity] || a.issue.name.localeCompare(b.issue.name));
    return rows;
}

/**
 * Render the Watchtower card body. `report === null` renders the
 * placeholder line (scan unavailable / not connected); a non-empty report
 * renders chips plus the (collapsed) hit list with an expand toggle.
 */
export function renderWatchtower(
    container: HTMLElement,
    report: WatchtowerReport | null,
    actions: WatchtowerActions
): void {
    container.textContent = '';

    if (!report) {
        const empty = document.createElement('div');
        empty.className = 'empty';
        empty.textContent = msg('popupWatchtowerUnavailable');
        container.appendChild(empty);
        return;
    }

    const chips = document.createElement('div');
    chips.className = 'wt-chips';
    let list: HTMLElement | null = null;
    let toggle: HTMLButtonElement | null = null;

    const setExpanded = (expanded: boolean) => {
        if (list) list.hidden = !expanded;
        if (toggle) toggle.setAttribute('aria-expanded', String(expanded));
    };

    for (const bucket of BUCKETS) {
        const count = report[bucket.key].length;
        const chip = document.createElement('button');
        chip.className = 'chip';
        chip.type = 'button';
        if (count === 0) chip.classList.add('dim');
        chip.textContent = `${msg(bucket.labelKey)} ${count}`;
        chip.setAttribute('aria-label', `${msg(bucket.labelKey)}: ${count}`);
        chip.addEventListener('click', () => {
            setExpanded(true);
            if (list) {
                const first = list.querySelector(`[data-bucket="${bucket.key}"]`);
                first?.scrollIntoView({ block: 'nearest' });
            }
        });
        chips.appendChild(chip);
    }
    container.appendChild(chips);

    const rows = watchtowerRows(report);
    if (rows.length === 0) {
        const clean = document.createElement('div');
        clean.className = 'empty';
        clean.textContent = msg('popupWatchtowerAllClear');
        container.appendChild(clean);
        return;
    }

    toggle = document.createElement('button');
    toggle.className = 'action secondary wt-toggle';
    toggle.type = 'button';
    toggle.setAttribute('aria-expanded', 'false');
    toggle.textContent = `${msg('popupWatchtowerShow')} (${rows.length})`;
    toggle.addEventListener('click', () => {
        const expanded = toggle?.getAttribute('aria-expanded') !== 'true';
        setExpanded(expanded);
        if (toggle) toggle.textContent = expanded
            ? msg('popupWatchtowerHide') ?? ''
            : `${msg('popupWatchtowerShow')} (${rows.length})`;
    });
    container.appendChild(toggle);

    list = document.createElement('div');
    list.className = 'itemlist';
    list.hidden = true;
    for (const { issue, bucket } of rows) {
        const row = document.createElement('button');
        row.className = 'item';
        row.type = 'button';
        row.dataset.itemId = issue.item_id;
        row.dataset.bucket = bucket.key;

        const glyph = document.createElement('div');
        glyph.className = 'glyph';
        glyph.textContent = bucket.glyph;
        row.appendChild(glyph);

        const meta = document.createElement('div');
        meta.className = 'meta';
        const t = document.createElement('div');
        t.className = 't';
        t.textContent = issue.name;
        meta.appendChild(t);
        const s = document.createElement('div');
        s.className = 's';
        s.textContent = `${msg(bucket.labelKey)} · ${issue.detail}`;
        meta.appendChild(s);
        row.appendChild(meta);

        const tail = document.createElement('div');
        tail.className = 'tail';
        tail.textContent = issue.severity;
        row.appendChild(tail);

        row.addEventListener('click', () => actions.onOpen(issue));
        list.appendChild(row);
    }
    container.appendChild(list);
}
