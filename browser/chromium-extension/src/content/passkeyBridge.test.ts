import {
    handlePasskeyPageMessage,
    replyToPage,
    fallbackToPage,
    PAGE_MESSAGE_SOURCE,
    CONTENT_MESSAGE_SOURCE
} from './passkeyBridge';
import { state } from './state';

function pageEvent(data: unknown): MessageEvent {
    return new MessageEvent('message', { source: window, data });
}

function foreignEvent(data: unknown): MessageEvent {
    return new MessageEvent('message', { source: {} as Window, data });
}

async function nextReply(): Promise<any> {
    return new Promise((resolve) => {
        const handler = (e: MessageEvent) => {
            if (e.data && e.data.source === CONTENT_MESSAGE_SOURCE) {
                window.removeEventListener('message', handler);
                resolve(e.data);
            }
        };
        window.addEventListener('message', handler);
    });
}

beforeEach(() => {
    state.passkeyOverlay = null;
    state.passkeyOverlayRequestId = null;
});

describe('handlePasskeyPageMessage', () => {
    it('ignores messages not posted by the page window itself', () => {
        expect(() =>
            handlePasskeyPageMessage(
                foreignEvent({ source: PAGE_MESSAGE_SOURCE, type: 'PERSONA_PASSKEY_CREATE' })
            )
        ).not.toThrow();
        expect(state.passkeyOverlayRequestId).toBeNull();
    });

    it('ignores messages from other sources', () => {
        const spy = jest.spyOn(window, 'postMessage').mockImplementation(() => {});
        handlePasskeyPageMessage(
            pageEvent({ source: 'something-else', type: 'PERSONA_PASSKEY_CREATE', requestId: 'r1' })
        );
        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });

    it('cancel clears the matching overlay request without replying', () => {
        const spy = jest.spyOn(window, 'postMessage').mockImplementation(() => {});
        state.passkeyOverlayRequestId = 'req-9';
        handlePasskeyPageMessage(
            pageEvent({ source: PAGE_MESSAGE_SOURCE, type: 'PERSONA_PASSKEY_CANCEL', requestId: 'req-9' })
        );
        expect(state.passkeyOverlayRequestId).toBeNull();
        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });

    it('create without a user gesture falls back to the page without a dialog', async () => {
        const reply = nextReply();
        handlePasskeyPageMessage(
            pageEvent({
                source: PAGE_MESSAGE_SOURCE,
                type: 'PERSONA_PASSKEY_CREATE',
                requestId: 'req-2',
                payload: { origin: window.location.origin }
            })
        );
        const data = await reply;
        expect(data.requestId).toBe('req-2');
        expect(data.type).toBe('PERSONA_PASSKEY_FALLBACK');
        expect(state.passkeyOverlayRequestId).toBeNull();
    });

    it('drops create requests from an origin that differs from the page', () => {
        const spy = jest.spyOn(window, 'postMessage').mockImplementation(() => {});
        handlePasskeyPageMessage(
            pageEvent({
                source: PAGE_MESSAGE_SOURCE,
                type: 'PERSONA_PASSKEY_CREATE',
                requestId: 'req-3',
                payload: { origin: 'https://evil.example' }
            })
        );
        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });

    it('drops get requests from an origin that differs from the page', () => {
        const spy = jest.spyOn(window, 'postMessage').mockImplementation(() => {});
        handlePasskeyPageMessage(
            pageEvent({
                source: PAGE_MESSAGE_SOURCE,
                type: 'PERSONA_PASSKEY_GET',
                requestId: 'req-4',
                payload: { origin: 'https://evil.example' }
            })
        );
        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });
});

describe('reply helpers', () => {
    it('replyToPage tags the reply with the content source and request id', async () => {
        const reply = nextReply();
        replyToPage('req-5', { type: 'PERSONA_PASSKEY_CREATE_OK' });
        const data = await reply;
        expect(data.source).toBe(CONTENT_MESSAGE_SOURCE);
        expect(data.requestId).toBe('req-5');
        expect(data.type).toBe('PERSONA_PASSKEY_CREATE_OK');
    });

    it('fallbackToPage signals fallback and clears overlay state', async () => {
        state.passkeyOverlayRequestId = 'req-6';
        const reply = nextReply();
        fallbackToPage('req-6');
        const data = await reply;
        expect(data.type).toBe('PERSONA_PASSKEY_FALLBACK');
        expect(state.passkeyOverlayRequestId).toBeNull();
    });
});
