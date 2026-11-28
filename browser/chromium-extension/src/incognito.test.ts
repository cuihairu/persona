/**
 * incognito tests: sender narrowing and the unified save-bar policy gate
 * (incognito > global setting > per-origin "never").
 */

import { isIncognitoSender, shouldSuppressSaveBar } from './incognito.js';


describe('incognito', () => {
    it('treats only an explicit tab.incognito=true as incognito', () => {
        expect(isIncognitoSender({ tab: { incognito: true } })).toBe(true);
        expect(isIncognitoSender({ tab: { incognito: false } })).toBe(false);
        expect(isIncognitoSender({ tab: {} })).toBe(false);
        expect(isIncognitoSender({})).toBe(false);
        expect(isIncognitoSender(null)).toBe(false);
        expect(isIncognitoSender(undefined)).toBe(false);
    });

    it('suppresses the save bar in incognito regardless of settings', () => {
        expect(shouldSuppressSaveBar({ isIncognito: true, savePromptEnabled: true })).toBe(true);
        expect(shouldSuppressSaveBar({ isIncognito: true, savePromptEnabled: false })).toBe(true);
        // even a site the user explicitly enabled-ish state stays suppressed
        expect(
            shouldSuppressSaveBar({ isIncognito: true, savePromptEnabled: true, savePromptDisabled: false })
        ).toBe(true);
    });

    it('keeps the existing non-incognito gates intact', () => {
        expect(shouldSuppressSaveBar({ isIncognito: false, savePromptEnabled: true })).toBe(false);
        expect(shouldSuppressSaveBar({ isIncognito: false, savePromptEnabled: true, savePromptDisabled: true })).toBe(true);
        expect(shouldSuppressSaveBar({ isIncognito: false, savePromptEnabled: true, savePromptDisabled: false })).toBe(false);
        expect(shouldSuppressSaveBar({ isIncognito: false, savePromptEnabled: false })).toBe(true);
    });
});
