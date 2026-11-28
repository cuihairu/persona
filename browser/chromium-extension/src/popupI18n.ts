/**
 * Popup HTML localization: Chrome substitutes __MSG_x__ placeholders in
 * manifest.json and CSS files only — in HTML pages they render as literal
 * `__MSG_...__` text (verified in a real Chromium on 2026-11-28). Shipping
 * markup therefore carries the en catalog strings as static defaults, and
 * this module overwrites them with the active-locale strings at init via
 * chrome.i18n.getMessage. Pure logic lives here so the contract can be
 * tested against the real popup.html (see popupI18n.test.ts).
 */

export interface PopupI18nEntry {
    /** element id in public/popup.html */
    id: string;
    key: string;
    /** when set, write to this attribute instead of textContent */
    attr?: string;
}

/** Every localized spot in popup.html, keyed by element id. */
export const POPUP_I18N: PopupI18nEntry[] = [
    { id: 'status', key: 'popupBridgeNotContacted' },
    { id: 'status', key: 'popupBridgeStatusTitle', attr: 'title' },
    { id: 'accountStatus', key: 'popupUnknown' },
    { id: 'accountStatus', key: 'popupAccountStatusTitle', attr: 'title' },
    { id: 'themeBtn', key: 'popupThemeToggleTitle', attr: 'title' },
    { id: 'themeBtn', key: 'popupThemeToggleTitle', attr: 'aria-label' },
    { id: 'searchInput', key: 'popupSearchPlaceholder', attr: 'placeholder' },
    { id: 'titleForThisSite', key: 'popupForThisSite' },
    { id: 'autofillStatus', key: 'popupSuggestionsUnavailable' },
    { id: 'titleVault', key: 'popupVault' },
    { id: 'cloudStatus', key: 'popupNotConnected' },
    { id: 'filterEmpty', key: 'popupFilterEmpty' },
    { id: 'titleWatchtower', key: 'popupWatchtower' },
    { id: 'titleGenerator', key: 'popupGenerator' },
    { id: 'genModeSeg', key: 'popupGenModeLabel', attr: 'aria-label' },
    { id: 'genModeChars', key: 'popupModeCharactersTitle', attr: 'title' },
    { id: 'genModeChars', key: 'popupModeCharacters' },
    { id: 'genModeWords', key: 'popupModePassphraseTitle', attr: 'title' },
    { id: 'genModeWords', key: 'popupModePassphrase' },
    { id: 'labelLength', key: 'popupLength' },
    { id: 'labelWords', key: 'popupWords' },
    { id: 'labelPronounceable', key: 'popupPronounceable' },
    { id: 'genGenerate', key: 'popupGenerate' },
    { id: 'genCopy', key: 'popupGenCopyTitle', attr: 'title' },
    { id: 'genCopy', key: 'popupGenCopy' },
    { id: 'genFill', key: 'popupGenFillTitle', attr: 'title' },
    { id: 'genFill', key: 'popupGenFill' },
    { id: 'detailEmpty', key: 'popupDetailEmpty' },
    { id: 'inlineMenuOnFocusLabel', key: 'popupInlineMenuOnFocus' },
    { id: 'inlineMenuNote', key: 'popupInlineMenuNote' },
];

/**
 * Apply locale strings to the popup markup. `t` resolves a key to its
 * message (empty string = unknown key: the static default stays). Returns
 * which entries found no element or no message so tests and the caller can
 * spot contract drift.
 */
export function applyPopupI18n(
    doc: Document,
    entries: PopupI18nEntry[],
    t: (key: string) => string
): { missingElement: string[]; missingMessage: string[] } {
    const missingElement: string[] = [];
    const missingMessage: string[] = [];
    for (const entry of entries) {
        const el = doc.getElementById(entry.id);
        if (!el) {
            missingElement.push(`${entry.id}:${entry.key}`);
            continue;
        }
        const message = t(entry.key);
        if (!message) {
            missingMessage.push(`${entry.id}:${entry.key}`);
            continue;
        }
        if (entry.attr) {
            el.setAttribute(entry.attr, message);
        } else {
            el.textContent = message;
        }
    }
    return { missingElement, missingMessage };
}
