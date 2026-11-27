/**
 * Watchtower card rendering: count chips per bucket, collapsed hit list
 * with severity-sorted rows, expand toggle, and click-through to the item
 * detail. Pure render — the only side effect is the onOpen callback.
 */

import { renderWatchtower, watchtowerRows, type WatchtowerIssue, type WatchtowerReport } from './popupWatchtower.js';

const EN_STRINGS: Record<string, string> = {
    popupWatchtowerWeak: 'Weak',
    popupWatchtowerReused: 'Reused',
    popupWatchtowerNoTotp: 'No 2FA',
    popupWatchtowerStale: 'Stale',
    popupWatchtowerUnavailable: 'Scan unavailable',
    popupWatchtowerAllClear: 'No issues found.',
    popupWatchtowerShow: 'Show issues',
    popupWatchtowerHide: 'Hide issues'
};

function issue(partial: Partial<WatchtowerIssue>): WatchtowerIssue {
    return {
        item_id: 'itm-' + Math.random().toString(36).slice(2),
        name: 'item',
        severity: 'low',
        detail: 'fact',
        ...partial
    };
}

const REPORT: WatchtowerReport = {
    scanned_at: '2026-11-28T00:00:00+00:00',
    total_credentials: 5,
    weak: [issue({ name: 'Blog admin', severity: 'high', detail: 'scores 0/4', score: 0 })],
    reused: [
        issue({ name: 'Repo admin', severity: 'high', detail: 'shared by 2', group_size: 2 }),
        issue({ name: 'Repo forum', severity: 'high', detail: 'shared by 2', group_size: 2 })
    ],
    no_totp: [issue({ name: 'Repo admin', severity: 'low', detail: 'github.com offers 2FA', site: 'github.com' })],
    stale: []
};

describe('watchtowerRows', () => {
    it('merges buckets with severity ordering and name tiebreak', () => {
        const rows = watchtowerRows(REPORT);
        expect(rows).toHaveLength(4);
        expect(rows.every((r) => r.issue.severity === 'high' || r.issue.severity === 'low')).toBe(true);
        // high before low; equal severity sorts by name
        const severities = rows.map((r) => r.issue.severity);
        expect(severities.indexOf('high')).toBeLessThan(severities.lastIndexOf('low'));
        const names = rows.filter((r) => r.issue.severity === 'high').map((r) => r.issue.name);
        expect(names).toEqual([...names].sort());
    });
});

describe('renderWatchtower', () => {
    let onOpen: jest.Mock;

    beforeEach(() => {
        document.body.innerHTML = '';
        onOpen = jest.fn();
        (globalThis as { chrome?: unknown }).chrome = {
            i18n: { getMessage: (key: string) => EN_STRINGS[key] ?? '' }
        };
    });

    afterEach(() => {
        delete (globalThis as { chrome?: unknown }).chrome;
    });

    function render(report: WatchtowerReport | null): HTMLElement {
        const container = document.createElement('div');
        document.body.appendChild(container);
        renderWatchtower(container, report, { onOpen });
        return container;
    }

    it('renders the unavailable placeholder for a null report', () => {
        const el = render(null);
        expect(el.querySelector('.empty')?.textContent).toBe('Scan unavailable');
        expect(el.querySelector('.wt-chips')).toBeNull();
    });

    it('renders one count chip per bucket with the bucket counts', () => {
        const el = render(REPORT);
        const chips = Array.from(el.querySelectorAll('.wt-chips .chip'));
        expect(chips.map((c) => c.textContent)).toEqual(['Weak 1', 'Reused 2', 'No 2FA 1', 'Stale 0']);
        expect(chips[3].classList.contains('dim')).toBe(true);
    });

    it('keeps the hit list collapsed until the toggle opens it', () => {
        const el = render(REPORT);
        const list = el.querySelector('.itemlist') as HTMLElement;
        expect(list.hidden).toBe(true);
        const toggle = el.querySelector('.wt-toggle') as HTMLButtonElement;
        expect(toggle.textContent).toContain('Show issues (4)');
        toggle.click();
        expect(list.hidden).toBe(false);
        expect(toggle.getAttribute('aria-expanded')).toBe('true');
        expect(toggle.textContent).toBe('Hide issues');
    });

    it('renders severity-sorted item rows with glyph, label and tail', () => {
        const el = render(REPORT);
        const toggle = el.querySelector('.wt-toggle') as HTMLButtonElement;
        toggle.click();
        const rows = Array.from(el.querySelectorAll('.item'));
        expect(rows).toHaveLength(4);
        const first = rows[0];
        expect(first.querySelector('.glyph')?.textContent).toBe('W');
        expect(first.querySelector('.meta .t')?.textContent).toBe('Blog admin');
        expect(first.querySelector('.meta .s')?.textContent).toContain('Weak · scores 0/4');
        expect(first.querySelector('.tail')?.textContent).toBe('high');
    });

    it('routes row clicks to onOpen with the underlying issue', () => {
        const el = render(REPORT);
        (el.querySelector('.wt-toggle') as HTMLButtonElement).click();
        const row = el.querySelector('[data-bucket="no_totp"]') as HTMLButtonElement;
        expect(row.dataset.itemId).toBe(REPORT.no_totp[0].item_id);
        row.click();
        expect(onOpen).toHaveBeenCalledTimes(1);
        expect(onOpen).toHaveBeenCalledWith(REPORT.no_totp[0]);
    });

    it('renders the all-clear line when every bucket is empty', () => {
        const clean: WatchtowerReport = {
            scanned_at: '2026-11-28T00:00:00+00:00',
            total_credentials: 3,
            weak: [],
            reused: [],
            no_totp: [],
            stale: []
        };
        const el = render(clean);
        expect(el.querySelector('.empty')?.textContent).toBe('No issues found.');
        expect(el.querySelector('.wt-toggle')).toBeNull();
    });
});
