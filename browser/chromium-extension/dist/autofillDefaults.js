export const AUTOFILL_DEFAULTS_KEY = 'persona_autofill_defaults_v1';
function normalizeOrigin(value) {
    try {
        return new URL(value).origin;
    }
    catch {
        return null;
    }
}
function normalizeDefaults(value) {
    const raw = value && typeof value === 'object' ? value : {};
    const out = {};
    for (const [origin, entry] of Object.entries(raw)) {
        const normalizedOrigin = normalizeOrigin(origin);
        if (!normalizedOrigin)
            continue;
        const e = entry && typeof entry === 'object' ? entry : {};
        const passwordItemId = typeof e.passwordItemId === 'string' && e.passwordItemId.trim() ? e.passwordItemId.trim() : undefined;
        const totpItemId = typeof e.totpItemId === 'string' && e.totpItemId.trim() ? e.totpItemId.trim() : undefined;
        if (!passwordItemId && !totpItemId)
            continue;
        out[normalizedOrigin] = {
            passwordItemId,
            totpItemId,
            updatedAt: typeof e.updatedAt === 'number' ? e.updatedAt : Date.now()
        };
    }
    return out;
}
export async function getAutofillDefaults() {
    return new Promise((resolve) => {
        chrome.storage.local.get(AUTOFILL_DEFAULTS_KEY, (value) => {
            resolve(normalizeDefaults(value?.[AUTOFILL_DEFAULTS_KEY]));
        });
    });
}
export async function getAutofillDefaultsForOrigin(origin) {
    const normalizedOrigin = normalizeOrigin(origin);
    if (!normalizedOrigin)
        return null;
    const all = await getAutofillDefaults();
    return all[normalizedOrigin] ?? null;
}
export async function setAutofillDefaultsForOrigin(origin, patch) {
    const normalizedOrigin = normalizeOrigin(origin);
    if (!normalizedOrigin)
        return null;
    const all = await getAutofillDefaults();
    const prev = all[normalizedOrigin] ?? { updatedAt: Date.now() };
    const next = {
        ...prev,
        ...patch,
        updatedAt: Date.now()
    };
    if (!next.passwordItemId && !next.totpItemId) {
        delete all[normalizedOrigin];
    }
    else {
        all[normalizedOrigin] = next;
    }
    await new Promise((resolve) => {
        chrome.storage.local.set({ [AUTOFILL_DEFAULTS_KEY]: all }, () => resolve());
    });
    return all[normalizedOrigin] ?? null;
}
export function onAutofillDefaultsChanged(listener) {
    const handler = (changes, areaName) => {
        if (areaName !== 'local')
            return;
        const change = changes?.[AUTOFILL_DEFAULTS_KEY];
        if (!change)
            return;
        listener(normalizeDefaults(change.newValue));
    };
    chrome.storage.onChanged.addListener(handler);
    return () => chrome.storage.onChanged.removeListener(handler);
}
//# sourceMappingURL=autofillDefaults.js.map