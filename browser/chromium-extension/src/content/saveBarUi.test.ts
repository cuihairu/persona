/**
 * Save bar UI glue: the username field is editable and a confirm sends the
 * edited value as the save request's username.
 */

import { renderSaveBar, hideSaveBar } from './saveBar.js';
import { mountPersonaUi } from '../shadowUi.js';
import { state } from './state.js';

type SendHandler = (message: { type?: string; request?: { username?: string } }) => unknown;

describe('renderSaveBar username editing', () => {
    let sendMessage: jest.Mock;
    let handler: SendHandler;

    beforeEach(() => {
        document.body.innerHTML = '';
        state.saveBar = null;
        state.visibleSaveKey = null;
        handler = () => Promise.resolve({ success: true, data: { name: 'saved item' } });
        sendMessage = jest.fn((message: { type?: string; request?: { username?: string } }) => handler(message));
        (globalThis as { chrome?: unknown }).chrome = {
            runtime: { sendMessage }
        };
    });

    afterEach(() => {
        hideSaveBar();
        delete (globalThis as { chrome?: unknown }).chrome;
    });

    function bar(): HTMLElement {
        // the bar lives inside the closed shadow root; the module-cached
        // mount is the only door in
        const el = mountPersonaUi(document).root.querySelector('.persona-save-bar');
        if (!el) throw new Error('save bar not rendered');
        return el as HTMLElement;
    }

    function usernameInput(): HTMLInputElement {
        const el = bar().querySelector('input[aria-label="Username"]');
        if (!el) throw new Error('username input missing');
        return el as HTMLInputElement;
    }

    it('pre-fills the username from the proposal', () => {
        renderSaveBar({ scenario: 'login', username: 'octo@example.com', password: 'pw' }, null);
        expect(usernameInput().value).toBe('octo@example.com');
    });

    it('renders an empty editable field when the proposal has no username', () => {
        renderSaveBar({ scenario: 'login', password: 'pw' }, null);
        expect(usernameInput().value).toBe('');
    });

    it('sends the edited username in the save request', async () => {
        renderSaveBar({ scenario: 'login', username: 'old@example.com', password: 'pw' }, null);
        usernameInput().value = 'new@example.com';
        (bar().querySelector('.p-btn') as HTMLButtonElement).click();
        await Promise.resolve();
        await Promise.resolve();
        expect(sendMessage).toHaveBeenCalledWith(
            expect.objectContaining({
                type: 'persona_save_credential',
                request: expect.objectContaining({ username: 'new@example.com', password: 'pw' })
            })
        );
    });

    it('sends an undefined username when the field is cleared', async () => {
        renderSaveBar({ scenario: 'login', username: 'old@example.com', password: 'pw' }, null);
        usernameInput().value = '';
        (bar().querySelector('.p-btn') as HTMLButtonElement).click();
        await Promise.resolve();
        await Promise.resolve();
        expect(sendMessage).toHaveBeenCalledWith(
            expect.objectContaining({
                type: 'persona_save_credential',
                request: expect.objectContaining({ username: undefined })
            })
        );
    });

    it('tracks the edited username in the visible-save dedupe key', () => {
        renderSaveBar({ scenario: 'login', username: 'old@example.com', password: 'pw' }, null);
        expect(state.visibleSaveKey).toBe('old@example.com|pw');
        usernameInput().value = 'new@example.com';
        usernameInput().dispatchEvent(new Event('input'));
        expect(state.visibleSaveKey).toBe('new@example.com|pw');
    });
});
