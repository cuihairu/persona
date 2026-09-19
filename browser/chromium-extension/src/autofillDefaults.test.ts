/**
 * autofillDefaults 测试：origin 归一化、空/垃圾条目过滤、按 origin 合并写与双空清除、
 * onChanged 订阅过滤。
 */
import {
    AUTOFILL_DEFAULTS_KEY,
    getAutofillDefaults,
    getAutofillDefaultsForOrigin,
    setAutofillDefaultsForOrigin,
    onAutofillDefaultsChanged,
    type AutofillDefaultsByOrigin
} from './autofillDefaults';

type ChangeRecord = Record<string, { newValue?: unknown }>;
type ChangeListener = (changes: ChangeRecord, areaName: string) => void;

/** chrome.storage.local + onChanged 的最小内存实现（同 settings.test.ts） */
function installChromeStorageMock() {
    const data = new Map<string, unknown>();
    const listeners = new Set<ChangeListener>();

    (globalThis as any).chrome = {
        storage: {
            local: {
                get: (keys: unknown, cb: (items: Record<string, unknown>) => void) => {
                    const key = keys as string;
                    const items = data.has(key) ? { [key]: data.get(key) } : {};
                    setTimeout(() => cb(items), 0);
                },
                set: (items: Record<string, unknown>, cb?: () => void) => {
                    for (const [key, value] of Object.entries(items)) data.set(key, value);
                    setTimeout(() => cb?.(), 0);
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

describe('getAutofillDefaults normalization', () => {
    it('returns an empty map on empty or non-object storage', async () => {
        expect(await getAutofillDefaults()).toEqual({});
        mock.seed(AUTOFILL_DEFAULTS_KEY, 'garbage');
        expect(await getAutofillDefaults()).toEqual({});
    });

    it('normalizes origins, drops invalid origins and empty entries', async () => {
        mock.seed(AUTOFILL_DEFAULTS_KEY, {
            'https://a.com': { passwordItemId: 'p1', totpItemId: 't1', updatedAt: 123 },
            'not a url': { passwordItemId: 'p2', updatedAt: 5 },
            'https://b.com/': { passwordItemId: '   ', updatedAt: 6 },
            'https://c.com': { totpItemId: '', updatedAt: 7 },
            'HTTPS://D.COM/path?q=1': { totpItemId: 't4' }
        });

        const defaults = await getAutofillDefaults();

        expect(Object.keys(defaults).sort()).toEqual(['https://a.com', 'https://d.com']);
        expect(defaults['https://a.com']).toEqual({
            passwordItemId: 'p1',
            totpItemId: 't1',
            updatedAt: 123
        });
        // updatedAt 缺失时回填当前时间戳；origin 归一化去掉了 path 与大小写
        expect(typeof defaults['https://d.com']!.updatedAt).toBe('number');
        expect(defaults['https://d.com']).toEqual({
            passwordItemId: undefined,
            totpItemId: 't4',
            updatedAt: expect.any(Number)
        });
    });
});

describe('getAutofillDefaultsForOrigin', () => {
    it('matches by normalized origin and returns null when absent', async () => {
        mock.seed(AUTOFILL_DEFAULTS_KEY, {
            'https://a.com': { passwordItemId: 'p1', updatedAt: 1 }
        });
        expect(await getAutofillDefaultsForOrigin('https://a.com/some/page')).toEqual({
            passwordItemId: 'p1',
            totpItemId: undefined,
            updatedAt: 1
        });
        expect(await getAutofillDefaultsForOrigin('https://other.com')).toBeNull();
    });

    it('returns null for unparseable origins', async () => {
        expect(await getAutofillDefaultsForOrigin('::bad::')).toBeNull();
    });
});

describe('setAutofillDefaultsForOrigin', () => {
    it('creates an entry and returns it', async () => {
        const entry = await setAutofillDefaultsForOrigin('https://e.com', { passwordItemId: 'p5' });
        expect(entry).toEqual({
            passwordItemId: 'p5',
            totpItemId: undefined,
            updatedAt: expect.any(Number)
        });
        expect(await getAutofillDefaultsForOrigin('https://e.com')).toEqual(entry);
    });

    it('merges with the previous entry instead of clobbering it', async () => {
        mock.seed(AUTOFILL_DEFAULTS_KEY, {
            'https://a.com': { passwordItemId: 'p1', updatedAt: 5 }
        });
        const entry = await setAutofillDefaultsForOrigin('https://a.com', { totpItemId: 't9' });
        expect(entry!.passwordItemId).toBe('p1');
        expect(entry!.totpItemId).toBe('t9');
        expect(entry!.updatedAt).toBeGreaterThan(5);
    });

    it('deletes the entry when both item ids end up empty', async () => {
        mock.seed(AUTOFILL_DEFAULTS_KEY, {
            'https://a.com': { passwordItemId: 'p1', totpItemId: 't1', updatedAt: 5 }
        });
        const result = await setAutofillDefaultsForOrigin('https://a.com', {
            passwordItemId: '',
            totpItemId: undefined
        });
        expect(result).toBeNull();
        expect(await getAutofillDefaultsForOrigin('https://a.com')).toBeNull();
        const all = await getAutofillDefaults();
        expect(all['https://a.com']).toBeUndefined();
    });

    it('refuses unparseable origins without writing', async () => {
        const result = await setAutofillDefaultsForOrigin('::bad::', { passwordItemId: 'p' });
        expect(result).toBeNull();
        expect(await getAutofillDefaults()).toEqual({});
    });
});

describe('onAutofillDefaultsChanged', () => {
    it('delivers normalized defaults and filters by key/area', () => {
        const seen: AutofillDefaultsByOrigin[] = [];
        const unsubscribe = onAutofillDefaultsChanged((defaults) => seen.push(defaults));

        mock.fire({ otherKey: { newValue: {} } }, 'local');
        mock.fire({ [AUTOFILL_DEFAULTS_KEY]: { newValue: {} } }, 'sync');
        expect(seen).toHaveLength(0);

        mock.fire(
            {
                [AUTOFILL_DEFAULTS_KEY]: {
                    newValue: { 'https://a.com': { passwordItemId: 'p1', updatedAt: 1 } }
                }
            },
            'local'
        );
        expect(seen).toHaveLength(1);
        expect(seen[0]['https://a.com']!.passwordItemId).toBe('p1');

        unsubscribe();
        mock.fire({ [AUTOFILL_DEFAULTS_KEY]: { newValue: {} } }, 'local');
        expect(seen).toHaveLength(1);
    });
});
