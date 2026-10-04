/**
 * pendingSave 测试：跨导航保存提案的存取契约 —— origin 严格绑定、TTL 过期、
 * read-and-clear 一次性语义、缺字段拒绝。chrome.storage.session 用内存实现。
 */
import {
    PENDING_SAVE_KEY,
    PENDING_SAVE_TTL_MS,
    clearPendingSave,
    isPendingSaveUsable,
    stashPendingSave,
    takePendingSave,
    type PendingSaveEntry
} from './pendingSave';

/** chrome.storage.session（MV3 内存区）的最小内存实现 */
function installSessionMock() {
    const session = new Map<string, unknown>();
    (globalThis as any).chrome = {
        storage: {
            session: {
                get: async (key: string) => (session.has(key) ? { [key]: session.get(key) } : {}),
                set: async (items: Record<string, unknown>) => {
                    for (const [k, v] of Object.entries(items)) session.set(k, v);
                },
                remove: async (key: string) => {
                    session.delete(key);
                }
            }
        }
    };
    return session;
}

const ENTRY: PendingSaveEntry = {
    origin: 'https://example.com',
    username: 'bob@example.com',
    password: 's3cret-new',
    scenario: 'login',
    nameHint: 'Example',
    at: 1_000_000
};

beforeEach(() => {
    installSessionMock();
});

describe('isPendingSaveUsable', () => {
    it('accepts a fresh entry for the exact origin', () => {
        expect(isPendingSaveUsable(ENTRY, 'https://example.com', 1_000_500)).toBe(true);
    });

    it('rejects a different origin (no subdomain/substring leniency)', () => {
        expect(isPendingSaveUsable(ENTRY, 'https://evil-example.com', 1_000_500)).toBe(false);
        expect(isPendingSaveUsable(ENTRY, 'https://sub.example.com', 1_000_500)).toBe(false);
        expect(isPendingSaveUsable(ENTRY, 'http://example.com', 1_000_500)).toBe(false);
    });

    it('rejects entries older than the TTL', () => {
        expect(isPendingSaveUsable(ENTRY, 'https://example.com', ENTRY.at + PENDING_SAVE_TTL_MS)).toBe(true);
        expect(
            isPendingSaveUsable(ENTRY, 'https://example.com', ENTRY.at + PENDING_SAVE_TTL_MS + 1)
        ).toBe(false);
    });

    it('rejects empty passwords and malformed entries', () => {
        expect(isPendingSaveUsable({ ...ENTRY, password: '' }, 'https://example.com')).toBe(false);
        expect(isPendingSaveUsable({ ...ENTRY, at: NaN }, 'https://example.com')).toBe(false);
        expect(isPendingSaveUsable(null, 'https://example.com')).toBe(false);
        expect(isPendingSaveUsable(undefined, 'https://example.com')).toBe(false);
    });
});

describe('takePendingSave', () => {
    it('restores once and clears the stash (no stacked bars on reload)', async () => {
        await stashPendingSave(ENTRY);
        const restored = await takePendingSave('https://example.com', ENTRY.at + 10);
        expect(restored).toEqual(ENTRY);
        expect(await takePendingSave('https://example.com', ENTRY.at + 20)).toBeNull();
    });

    it('drops a stash aimed at another origin', async () => {
        await stashPendingSave(ENTRY);
        expect(await takePendingSave('https://other.test', ENTRY.at + 10)).toBeNull();
        // ... and it is not left behind for later.
        expect(await takePendingSave('https://example.com', ENTRY.at + 20)).toBeNull();
    });

    it('drops an expired stash instead of serving it', async () => {
        await stashPendingSave(ENTRY);
        const late = ENTRY.at + PENDING_SAVE_TTL_MS + 1;
        expect(await takePendingSave('https://example.com', late)).toBeNull();
        expect(await takePendingSave('https://example.com', late)).toBeNull();
    });

    it('returns null when nothing was stashed', async () => {
        expect(await takePendingSave('https://example.com')).toBeNull();
    });

    it('clearPendingSave wipes the entry', async () => {
        await stashPendingSave(ENTRY);
        await clearPendingSave();
        expect(await takePendingSave('https://example.com')).toBeNull();
    });
});