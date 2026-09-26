import {
  checkForUpdate,
  compareVersions,
  getBuildMeta,
  getLastCheckedAt,
  isUpdateCheckEnabled,
  setLastCheckedAt,
  setUpdateCheckEnabled,
  UPDATE_CHECK_ENABLED_KEY,
} from './updateCheck';
import { getVersion } from '@tauri-apps/api/app';

jest.mock('@tauri-apps/api/app', () => ({
  getVersion: jest.fn(),
}));

const mockGetVersion = getVersion as jest.Mock;

type FakeResponse = { status: number; ok: boolean; payload?: unknown };

/** 极简 Response 桩：只实现 checkForUpdate 用到的三个面 */
const fakeFetch = (responsesByMatcher: Array<{ match: (url: string) => boolean; response: FakeResponse | Error }>) => {
  return jest.fn(async (url: string) => {
    const hit = responsesByMatcher.find((entry) => entry.match(url));
    if (!hit) throw new Error(`unexpected fetch: ${url}`);
    if (hit.response instanceof Error) throw hit.response;
    const { status, ok, payload } = hit.response;
    return {
      status,
      ok,
      json: async () => payload,
    } as unknown as Response;
  });
};

const RELEASE_LATEST = (url: string) => url.endsWith('/releases/latest');
const WORKFLOW_RUNS = (url: string) => url.includes('/actions/workflows/desktop-build.yml/runs');

/** 设定构建元信息（globalThis 上直接放 __PERSONA_BUILD__，对齐 vite define 注入点） */
const setBuildMeta = (meta: { channel: string; sha?: string; builtAt?: string }) => {
  (globalThis as Record<string, unknown>).__PERSONA_BUILD__ = {
    channel: meta.channel,
    sha: meta.sha ?? '',
    builtAt: meta.builtAt ?? '',
  };
};

let savedMeta: unknown;

beforeEach(() => {
  savedMeta = (globalThis as Record<string, unknown>).__PERSONA_BUILD__;
  window.localStorage.clear();
  mockGetVersion.mockReset();
  mockGetVersion.mockResolvedValue('0.1.0');
});

afterEach(() => {
  (globalThis as Record<string, unknown>).__PERSONA_BUILD__ = savedMeta;
});

describe('utils/updateCheck compareVersions', () => {
  it('compares dotted numeric segments with v prefix tolerance', () => {
    expect(compareVersions('0.2.0', '0.1.9')).toBe(1);
    expect(compareVersions('v0.2.0', '0.2.0')).toBe(0);
    expect(compareVersions('0.1', '0.1.0')).toBe(0);
    expect(compareVersions('0.0.9', '0.1.0')).toBe(-1);
    expect(compareVersions('1.2.10', '1.2.9')).toBe(1);
  });

  it('returns null for non-numeric versions instead of guessing', () => {
    expect(compareVersions('latest', '0.1.0')).toBeNull();
    expect(compareVersions('0.1.x', '0.1.0')).toBeNull();
  });
});

describe('utils/updateCheck getBuildMeta', () => {
  it('falls back to dev when nothing is injected (jest)', () => {
    delete (globalThis as Record<string, unknown>).__PERSONA_BUILD__;
    expect(getBuildMeta()).toEqual({ channel: 'dev', sha: '', builtAt: '' });
  });

  it('returns the injected meta as-is', () => {
    setBuildMeta({ channel: 'nightly', sha: 'abc123', builtAt: '2026-09-26T10:00:00Z' });
    expect(getBuildMeta()).toEqual({ channel: 'nightly', sha: 'abc123', builtAt: '2026-09-26T10:00:00Z' });
  });
});

describe('utils/updateCheck checkForUpdate', () => {
  it('dev channel short-circuits without any network call', async () => {
    setBuildMeta({ channel: 'dev' });
    const fetchFn = fakeFetch([]);
    const result = await checkForUpdate({ fetchFn });
    expect(result).toMatchObject({ status: 'unavailable', reason: 'dev-channel', channel: 'dev' });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('release channel reports an available newer tag', async () => {
    setBuildMeta({ channel: 'release' });
    const fetchFn = fakeFetch([
      {
        match: RELEASE_LATEST,
        response: { status: 200, ok: true, payload: { tag_name: 'v0.2.0', html_url: 'https://github.com/cuihairu/persona/releases/tag/v0.2.0' } },
      },
    ]);
    const result = await checkForUpdate({ fetchFn });
    expect(result).toMatchObject({
      status: 'update-available',
      latestVersion: 'v0.2.0',
      detailUrl: 'https://github.com/cuihairu/persona/releases/tag/v0.2.0',
      currentVersion: '0.1.0',
    });
  });

  it('release channel is up to date on the same version', async () => {
    setBuildMeta({ channel: 'release' });
    const fetchFn = fakeFetch([
      { match: RELEASE_LATEST, response: { status: 200, ok: true, payload: { tag_name: 'v0.1.0' } } },
    ]);
    const result = await checkForUpdate({ fetchFn });
    expect(result.status).toBe('up-to-date');
  });

  it('release 404 (no releases yet) maps to no-release', async () => {
    setBuildMeta({ channel: 'release' });
    const fetchFn = fakeFetch([{ match: RELEASE_LATEST, response: { status: 404, ok: false } }]);
    const result = await checkForUpdate({ fetchFn });
    expect(result).toMatchObject({ status: 'unavailable', reason: 'no-release' });
  });

  it('release channel without a readable current version maps to no-current-version', async () => {
    setBuildMeta({ channel: 'release' });
    mockGetVersion.mockRejectedValue(new Error('no __TAURI_INTERNALS__'));
    const fetchFn = fakeFetch([]);
    const result = await checkForUpdate({ fetchFn });
    expect(result).toMatchObject({ status: 'unavailable', reason: 'no-current-version' });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('network failures fold into unavailable/network instead of throwing', async () => {
    setBuildMeta({ channel: 'release' });
    const fetchFn = fakeFetch([{ match: RELEASE_LATEST, response: new Error('offline') }]);
    const result = await checkForUpdate({ fetchFn });
    expect(result).toMatchObject({ status: 'unavailable', reason: 'network' });
  });

  it('nightly channel is up to date when the latest run built this commit', async () => {
    setBuildMeta({ channel: 'nightly', sha: 'feedbee', builtAt: '2026-09-26T10:00:00Z' });
    const fetchFn = fakeFetch([
      {
        match: WORKFLOW_RUNS,
        response: {
          status: 200,
          ok: true,
          payload: { workflow_runs: [{ head_sha: 'feedbee', created_at: '2026-09-26T09:30:00Z', html_url: 'https://github.com/cuihairu/persona/actions/runs/1' }] },
        },
      },
    ]);
    const result = await checkForUpdate({ fetchFn });
    expect(result).toMatchObject({ status: 'up-to-date', latestVersion: 'feedbee' });
  });

  it('nightly channel reports an update when a newer run exists on another commit', async () => {
    setBuildMeta({ channel: 'nightly', sha: 'oldcommit', builtAt: '2026-09-25T10:00:00Z' });
    const fetchFn = fakeFetch([
      {
        match: WORKFLOW_RUNS,
        response: {
          status: 200,
          ok: true,
          payload: { workflow_runs: [{ head_sha: 'newcommit', created_at: '2026-09-26T08:00:00Z', html_url: 'https://github.com/cuihairu/persona/actions/runs/2' }] },
        },
      },
    ]);
    const result = await checkForUpdate({ fetchFn });
    expect(result).toMatchObject({
      status: 'update-available',
      latestVersion: 'newcomm',
      detailUrl: 'https://github.com/cuihairu/persona/actions/runs/2',
    });
  });

  it('nightly channel ignores an older run of another commit', async () => {
    setBuildMeta({ channel: 'nightly', sha: 'freshcommit', builtAt: '2026-09-26T10:00:00Z' });
    const fetchFn = fakeFetch([
      {
        match: WORKFLOW_RUNS,
        response: {
          status: 200,
          ok: true,
          payload: { workflow_runs: [{ head_sha: 'oldcommit', created_at: '2026-09-25T08:00:00Z' }] },
        },
      },
    ]);
    const result = await checkForUpdate({ fetchFn });
    expect(result.status).toBe('up-to-date');
  });

  it('nightly channel with no successful runs maps to no-release', async () => {
    setBuildMeta({ channel: 'nightly', sha: 'x' });
    const fetchFn = fakeFetch([
      { match: WORKFLOW_RUNS, response: { status: 200, ok: true, payload: { workflow_runs: [] } } },
    ]);
    const result = await checkForUpdate({ fetchFn });
    expect(result).toMatchObject({ status: 'unavailable', reason: 'no-release' });
  });
});

describe('utils/updateCheck persistence', () => {
  it('defaults to enabled when nothing is stored', () => {
    expect(isUpdateCheckEnabled()).toBe(true);
  });

  it('persists the opt-out under the documented key', () => {
    setUpdateCheckEnabled(false);
    expect(isUpdateCheckEnabled()).toBe(false);
    expect(window.localStorage.getItem(UPDATE_CHECK_ENABLED_KEY)).toBe('0');
    setUpdateCheckEnabled(true);
    expect(isUpdateCheckEnabled()).toBe(true);
  });

  it('round-trips the last checked timestamp', () => {
    expect(getLastCheckedAt()).toBeNull();
    setLastCheckedAt('2026-09-26T10:00:00Z');
    expect(getLastCheckedAt()).toBe('2026-09-26T10:00:00Z');
  });
});
