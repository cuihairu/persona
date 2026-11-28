/**
 * settings tests: normalize's boolean-string coercion / numeric clamping / garbage-input fallback to defaults,
 * plus the read, write, and subscription semantics of chrome.storage.local + onChanged.
 */
import {
    AUTOFILL_SETTINGS_KEY,
    DEFAULT_AUTOFILL_SETTINGS,
    getAutofillSettings,
    setAutofillSettings,
    onAutofillSettingsChanged,
    type AutofillSettings
} from './settings';

type ChangeRecord = Record<string, { newValue?: unknown }>;
type ChangeListener = (changes: ChangeRecord, areaName: string) => void;

/** Minimal in-memory implementation of chrome.storage.local + onChanged */
function installChromeStorageMock() {
    const data = new Map<string, unknown>();
    const listeners = new Set<ChangeListener>();

    (globalThis as any).chrome = {
        storage: {
            local: {
                get: (keys: unknown, cb: (items: Record<string, unknown>) => void) => {
                    const wanted: string[] =
                        typeof keys === 'string'
                            ? [keys]
                            : Array.isArray(keys)
                            ? (keys as string[])
                            : keys && typeof keys === 'object'
                            ? Object.keys(keys as object)
                            : [...data.keys()];
                    const items: Record<string, unknown> = {};
                    for (const key of wanted) {
                        if (data.has(key)) items[key] = data.get(key);
                    }
                    setTimeout(() => cb(items), 0);
                },
                set: (items: Record<string, unknown>, cb?: () => void) => {
                    const changes: ChangeRecord = {};
                    for (const [key, value] of Object.entries(items)) {
                        changes[key] = { newValue: value };
                        data.set(key, value);
                    }
                    setTimeout(() => {
                        listeners.forEach((listener) => listener(changes, 'local'));
                        cb?.();
                    }, 0);
                }
            },
            onChanged: {
                addListener: (listener: ChangeListener) => listeners.add(listener),
                removeListener: (listener: ChangeListener) => listeners.delete(listener)
            }
        }
    };

    return {
        seed: (key: string, value: unknown) => data.set(key, value),
        /** Manually fire the onChanged listeners (any area may be named, for filtering assertions) */
        fire: (changes: ChangeRecord, areaName: string) => {
            listeners.forEach((listener) => listener(changes, areaName));
        },
        teardown: () => {
            listeners.clear();
            delete (globalThis as any).chrome;
        }
    };
}

let mock: ReturnType<typeof installChromeStorageMock>;

beforeEach(() => {
    mock = installChromeStorageMock();
});

afterEach(() => {
    mock.teardown();
});

describe('getAutofillSettings normalization', () => {
    it('returns defaults on empty storage', async () => {
        const settings = await getAutofillSettings();
        expect(settings).toEqual(DEFAULT_AUTOFILL_SETTINGS);
    });

    it('returns defaults when the stored value is not an object', async () => {
        mock.seed(AUTOFILL_SETTINGS_KEY, 'oops');
        expect(await getAutofillSettings()).toEqual(DEFAULT_AUTOFILL_SETTINGS);
    });

    it('coerces "true"/"false" strings into booleans', async () => {
        mock.seed(AUTOFILL_SETTINGS_KEY, {
            autoFillLoginOnFocus: 'false',
            autoFillLoginOnLoad: 'true',
            autoFillTotpOnFocus: 'false',
            autoFillTotpAfterLogin: 'false',
            requireTrustedDomain: 'true'
        });
        const settings = await getAutofillSettings();
        expect(settings.autoFillLoginOnFocus).toBe(false);
        expect(settings.autoFillLoginOnLoad).toBe(true);
        expect(settings.autoFillTotpOnFocus).toBe(false);
        expect(settings.autoFillTotpAfterLogin).toBe(false);
        expect(settings.requireTrustedDomain).toBe(true);
    });

    it('falls back to defaults for garbage boolean values', async () => {
        mock.seed(AUTOFILL_SETTINGS_KEY, { requireTrustedDomain: 'nope', autoFillLoginOnFocus: 42 });
        const settings = await getAutofillSettings();
        expect(settings.requireTrustedDomain).toBe(true);
        expect(settings.autoFillLoginOnFocus).toBe(true);
    });

    it('clamps match strengths into 0..100 and rounds', async () => {
        mock.seed(AUTOFILL_SETTINGS_KEY, {
            minMatchStrengthLogin: '75',
            minMatchStrengthTotp: 88.6
        });
        const settings = await getAutofillSettings();
        expect(settings.minMatchStrengthLogin).toBe(75);
        expect(settings.minMatchStrengthTotp).toBe(89);
    });

    it('clamps out-of-range strengths and falls back on NaN', async () => {
        mock.seed(AUTOFILL_SETTINGS_KEY, {
            minMatchStrengthLogin: 150,
            minMatchStrengthTotp: -3
        });
        expect((await getAutofillSettings()).minMatchStrengthLogin).toBe(100);
        expect((await getAutofillSettings()).minMatchStrengthTotp).toBe(0);

        mock.seed(AUTOFILL_SETTINGS_KEY, { minMatchStrengthLogin: 'abc' });
        expect((await getAutofillSettings()).minMatchStrengthLogin).toBe(
            DEFAULT_AUTOFILL_SETTINGS.minMatchStrengthLogin
        );
    });
});

describe('setAutofillSettings', () => {
    it('merges the patch over current settings and persists the normalized result', async () => {
        mock.seed(AUTOFILL_SETTINGS_KEY, { minMatchStrengthLogin: 50 });

        const next = await setAutofillSettings({ autoFillLoginOnLoad: true });

        expect(next.autoFillLoginOnLoad).toBe(true);
        expect(next.minMatchStrengthLogin).toBe(50);
        expect(next.autoFillLoginOnFocus).toBe(true);

        const stored = await getAutofillSettings();
        expect(stored).toEqual(next);
    });

    it('normalizes the patch itself (clamp + coerce)', async () => {
        const next = await setAutofillSettings({
            minMatchStrengthTotp: 200,
            requireTrustedDomain: 'false' as unknown as boolean
        });
        expect(next.minMatchStrengthTotp).toBe(100);
        expect(next.requireTrustedDomain).toBe(false);
    });

    it('defaults inlineMenuOnFocus on and coerces its stored value', async () => {
        // fresh storage: the 1Password-style default is on
        expect((await getAutofillSettings()).inlineMenuOnFocus).toBe(true);

        mock.seed(AUTOFILL_SETTINGS_KEY, { inlineMenuOnFocus: 'false' });
        expect((await getAutofillSettings()).inlineMenuOnFocus).toBe(false);

        mock.seed(AUTOFILL_SETTINGS_KEY, { inlineMenuOnFocus: 'junk' });
        expect((await getAutofillSettings()).inlineMenuOnFocus).toBe(true);
    });
});

describe('onAutofillSettingsChanged', () => {
    it('delivers normalized settings and stops after unsubscribe', () => {
        const seen: AutofillSettings[] = [];
        const unsubscribe = onAutofillSettingsChanged((settings) => seen.push(settings));

        mock.fire({ [AUTOFILL_SETTINGS_KEY]: { newValue: { minMatchStrengthLogin: 42 } } }, 'local');

        expect(seen).toHaveLength(1);
        expect(seen[0].minMatchStrengthLogin).toBe(42);
        expect(seen[0].autoFillLoginOnFocus).toBe(true); // omitted fields are backfilled with defaults

        unsubscribe();
        mock.fire({ [AUTOFILL_SETTINGS_KEY]: { newValue: {} } }, 'local');
        expect(seen).toHaveLength(1);
    });

    it('ignores other keys and non-local storage areas', () => {
        const seen: AutofillSettings[] = [];
        const unsubscribe = onAutofillSettingsChanged((settings) => seen.push(settings));

        mock.fire({ someOtherKey: { newValue: {} } }, 'local');
        mock.fire({ [AUTOFILL_SETTINGS_KEY]: { newValue: {} } }, 'sync');
        expect(seen).toHaveLength(0);

        mock.fire({ [AUTOFILL_SETTINGS_KEY]: { newValue: { minMatchStrengthTotp: 10 } } }, 'local');
        expect(seen).toHaveLength(1);
        expect(seen[0].minMatchStrengthTotp).toBe(10);

        unsubscribe();
    });
});
