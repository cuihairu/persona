/**
 * Detail-pane tests (jsdom): row construction, copy outcome wiring, live
 * 2FA countdown with fake timers, and ticker cleanup on re-render.
 */

import { renderDetail, clearTotpTicker, groupCode, type DetailActions, type DetailTarget } from './popupDetail.js';

function makeTarget(overrides: Partial<DetailTarget> = {}): DetailTarget {
    return {
        itemId: 'it-1',
        title: 'GitHub',
        subtitle: 'octo@example.com',
        credentialType: 'password',
        url: 'https://github.com',
        source: 'vault',
        ...overrides
    };
}

function makeActions(overrides: Partial<DetailActions> = {}): DetailActions {
    return {
        copyField: jest.fn().mockResolvedValue({ ok: true }),
        loadTotp: jest.fn().mockResolvedValue({ code: '123456', remainingSeconds: 30, period: 30 }),
        ...overrides
    };
}

async function flush(): Promise<void> {
    await Promise.resolve();
    await Promise.resolve();
}

describe('groupCode', () => {
    it('groups a 6-digit code in threes', () => {
        expect(groupCode('123456')).toBe('123 456');
    });

    it('balances an 8-digit code into two fours', () => {
        expect(groupCode('12345678')).toBe('1234 5678');
    });

    it('strips existing spaces before regrouping', () => {
        expect(groupCode('12 3456')).toBe('123 456');
    });

    it('leaves short codes alone', () => {
        expect(groupCode('1234')).toBe('1234');
    });
});

describe('renderDetail', () => {
    beforeEach(() => {
        document.body.innerHTML = '';
        jest.clearAllMocks();
    });

    it('builds header and field rows', () => {
        const root = document.createElement('div');
        document.body.appendChild(root);
        renderDetail(root, makeTarget(), makeActions());

        expect(root.querySelector('.detail-head .t')?.textContent).toBe('GitHub');
        expect(root.querySelector('.detail-head .s')?.textContent).toBe('octo@example.com');
        expect(root.querySelector('.detail-head .chip')?.textContent).toBe('password');

        const labels = Array.from(root.querySelectorAll('.drow .dlabel')).map((el) => el.textContent);
        expect(labels).toEqual(['Username', 'Password', '2FA']);

        const password = root.querySelectorAll('.drow .dvalue')[1] as HTMLElement;
        expect(password.classList.contains('dots')).toBe(true);
        expect(password.textContent).toContain('•');
    });

    it('shows the fill button only when a fill action is provided', () => {
        const withFill = document.createElement('div');
        document.body.appendChild(withFill);
        renderDetail(withFill, makeTarget({ source: 'suggestion' }), makeActions({ fill: () => {}, fillLabel: 'Fill login' }));
        expect(withFill.querySelector('button.action:not(.secondary)')?.textContent).toBe('Fill login');

        const withoutFill = document.createElement('div');
        document.body.appendChild(withoutFill);
        renderDetail(withoutFill, makeTarget(), makeActions());
        expect(withoutFill.querySelector('button.action:not(.secondary)')).toBeNull();
    });

    it('wires the copy button to copyField and announces success', async () => {
        const root = document.createElement('div');
        document.body.appendChild(root);
        const actions = makeActions({ copyField: jest.fn().mockResolvedValue({ ok: true }) });
        renderDetail(root, makeTarget(), actions);

        const copyPassword = Array.from(root.querySelectorAll('.drow button')).find(
            (b) => b.closest('.drow')?.querySelector('.dlabel')?.textContent === 'Password'
        ) as HTMLButtonElement;
        copyPassword.click();
        await flush();

        expect(actions.copyField).toHaveBeenCalledWith('password');
        const status = root.querySelector('[data-role="status"]') as HTMLElement;
        expect(status.textContent).toBe('Copied password');
        expect(status.classList.contains('err')).toBe(false);
    });

    it('announces copy failures with the error class', async () => {
        const root = document.createElement('div');
        document.body.appendChild(root);
        const actions = makeActions({
            copyField: jest.fn().mockResolvedValue({ ok: false, error: 'bridge not connected' })
        });
        renderDetail(root, makeTarget(), actions);

        const copyUsername = Array.from(root.querySelectorAll('.drow button')).find(
            (b) => b.closest('.drow')?.querySelector('.dlabel')?.textContent === 'Username'
        ) as HTMLButtonElement;
        copyUsername.click();
        await flush();

        const status = root.querySelector('[data-role="status"]') as HTMLElement;
        expect(status.textContent).toContain('bridge not connected');
        expect(status.classList.contains('err')).toBe(true);
    });

    it('keeps the password value masked even when a username is present', () => {
        const root = document.createElement('div');
        document.body.appendChild(root);
        renderDetail(root, makeTarget(), makeActions());
        const values = Array.from(root.querySelectorAll('.drow .dvalue')).map((el) => el.textContent ?? '');
        expect(values.some((v) => v.includes('octo@example.com') && v.includes('••••'))).toBe(false);
        expect(values[1]).toBe('••••••••');
    });
});

describe('renderDetail 2FA ticker', () => {
    beforeEach(() => {
        document.body.innerHTML = '';
        jest.useFakeTimers();
        jest.clearAllMocks();
    });

    afterEach(() => {
        clearTotpTicker();
        jest.useRealTimers();
    });

    async function showCode(root: HTMLElement, actions: DetailActions): Promise<HTMLElement> {
        renderDetail(root, makeTarget(), actions);
        const loadBtn = root.querySelector('[data-role="totp-load"]') as HTMLButtonElement;
        loadBtn.click();
        await flush();
        return root.querySelector('[data-role="totp-slot"]') as HTMLElement;
    }

    it('renders the grouped code after load', async () => {
        const root = document.createElement('div');
        document.body.appendChild(root);
        const slot = await showCode(root, makeActions());
        expect(slot.textContent).toBe('123 456');
        expect(slot.parentElement?.querySelector('.totp-bar')).not.toBeNull();
    });

    it('counts down and refreshes at expiry', async () => {
        const root = document.createElement('div');
        document.body.appendChild(root);
        const loadTotp = jest.fn()
            .mockResolvedValueOnce({ code: '111111', remainingSeconds: 2, period: 30 })
            .mockResolvedValueOnce({ code: '222222', remainingSeconds: 30, period: 30 });
        const slot = await showCode(root, makeActions({ loadTotp }));

        jest.advanceTimersByTime(1000);
        expect(slot.textContent).toBe('111 111'); // 1s left, still first code

        jest.advanceTimersByTime(1000); // hits zero -> reload
        await flush();
        expect(loadTotp).toHaveBeenCalledTimes(2);
        expect(slot.textContent).toBe('222 222');
    });

    it('clearTotpTicker stops the countdown and drops stale loads', async () => {
        const root = document.createElement('div');
        document.body.appendChild(root);
        const loadTotp = jest.fn().mockResolvedValue({ code: '999999', remainingSeconds: 5, period: 30 });
        await showCode(root, makeActions({ loadTotp }));
        expect(loadTotp).toHaveBeenCalledTimes(1);

        clearTotpTicker();
        jest.advanceTimersByTime(60000);
        await flush();
        expect(loadTotp).toHaveBeenCalledTimes(1); // no refresh after clear
    });

    it('shows an error inline when the load fails', async () => {
        const root = document.createElement('div');
        document.body.appendChild(root);
        const slot = await showCode(root, makeActions({
            loadTotp: jest.fn().mockResolvedValue({ error: 'no totp secret' })
        }));
        expect(slot.textContent).toBe('unavailable');
        const status = root.querySelector('[data-role="status"]') as HTMLElement;
        expect(status.textContent).toContain('no totp secret');
    });
});

describe('renderDetail clipboard clear countdown', () => {
    beforeEach(() => {
        document.body.innerHTML = '';
        jest.useFakeTimers();
        jest.clearAllMocks();
    });

    afterEach(() => {
        clearTotpTicker();
        jest.useRealTimers();
    });

    it('counts down to clipboard clear and reports it', async () => {
        const root = document.createElement('div');
        document.body.appendChild(root);
        const actions = makeActions({
            copyField: jest.fn().mockResolvedValue({ ok: true, clearAfterSeconds: 2 })
        });
        renderDetail(root, makeTarget(), actions);
        const copyPassword = Array.from(root.querySelectorAll('.drow button')).find(
            (b) => b.closest('.drow')?.querySelector('.dlabel')?.textContent === 'Password'
        ) as HTMLButtonElement;
        copyPassword.click();
        await flush();

        const status = root.querySelector('[data-role="status"]') as HTMLElement;
        expect(status.textContent).toContain('clears in 2s');

        jest.advanceTimersByTime(1000);
        expect(status.textContent).toContain('clears in 1s');

        jest.advanceTimersByTime(1000);
        expect(status.textContent).toBe('Clipboard cleared');
    });
});
