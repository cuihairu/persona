import { observeForms } from './formScanner';

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === 'persona_status') {
        console.debug('Persona status update', message.status);
        sendResponse({ ok: true });
    }
    return false;
});

observeForms((forms) => {
    chrome.runtime.sendMessage({
        type: 'persona_forms_snapshot',
        host: location.host,
        forms
    });
});
