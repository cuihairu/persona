export const AUTOFILL_SETTINGS_KEY = 'persona_autofill_settings_v1';

export interface AutofillSettings {
    autoFillLoginOnFocus: boolean;
    autoFillLoginOnLoad: boolean;
    autoFillTotpOnFocus: boolean;
    requireTrustedDomain: boolean;
    minMatchStrengthLogin: number;
    minMatchStrengthTotp: number;
}

export const DEFAULT_AUTOFILL_SETTINGS: AutofillSettings = {
    autoFillLoginOnFocus: true,
    autoFillLoginOnLoad: false,
    autoFillTotpOnFocus: true,
    requireTrustedDomain: true,
    minMatchStrengthLogin: 90,
    minMatchStrengthTotp: 90
};

function clampMatchStrength(value: unknown, fallback: number): number {
    const parsed = typeof value === 'number' ? value : Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(0, Math.min(100, Math.round(parsed)));
}

function coerceBoolean(value: unknown, fallback: boolean): boolean {
    if (typeof value === 'boolean') return value;
    if (value === 'true') return true;
    if (value === 'false') return false;
    return fallback;
}

function normalizeSettings(value: any): AutofillSettings {
    const raw = value && typeof value === 'object' ? value : {};
    return {
        autoFillLoginOnFocus: coerceBoolean(raw.autoFillLoginOnFocus, DEFAULT_AUTOFILL_SETTINGS.autoFillLoginOnFocus),
        autoFillLoginOnLoad: coerceBoolean(raw.autoFillLoginOnLoad, DEFAULT_AUTOFILL_SETTINGS.autoFillLoginOnLoad),
        autoFillTotpOnFocus: coerceBoolean(raw.autoFillTotpOnFocus, DEFAULT_AUTOFILL_SETTINGS.autoFillTotpOnFocus),
        requireTrustedDomain: coerceBoolean(raw.requireTrustedDomain, DEFAULT_AUTOFILL_SETTINGS.requireTrustedDomain),
        minMatchStrengthLogin: clampMatchStrength(raw.minMatchStrengthLogin, DEFAULT_AUTOFILL_SETTINGS.minMatchStrengthLogin),
        minMatchStrengthTotp: clampMatchStrength(raw.minMatchStrengthTotp, DEFAULT_AUTOFILL_SETTINGS.minMatchStrengthTotp)
    };
}

export async function getAutofillSettings(): Promise<AutofillSettings> {
    return new Promise((resolve) => {
        chrome.storage.local.get(AUTOFILL_SETTINGS_KEY, (value) => {
            resolve(normalizeSettings(value?.[AUTOFILL_SETTINGS_KEY]));
        });
    });
}

export async function setAutofillSettings(patch: Partial<AutofillSettings>): Promise<AutofillSettings> {
    const current = await getAutofillSettings();
    const next = normalizeSettings({ ...current, ...patch });
    await new Promise<void>((resolve) => {
        chrome.storage.local.set({ [AUTOFILL_SETTINGS_KEY]: next }, () => resolve());
    });
    return next;
}

export function onAutofillSettingsChanged(listener: (settings: AutofillSettings) => void): () => void {
    const handler: Parameters<typeof chrome.storage.onChanged.addListener>[0] = (changes, areaName) => {
        if (areaName !== 'local') return;
        const change = changes?.[AUTOFILL_SETTINGS_KEY];
        if (!change) return;
        listener(normalizeSettings(change.newValue));
    };
    chrome.storage.onChanged.addListener(handler);
    return () => chrome.storage.onChanged.removeListener(handler);
}

