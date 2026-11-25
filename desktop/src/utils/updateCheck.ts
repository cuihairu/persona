import { getVersion } from '@tauri-apps/api/app';

/**
 * Desktop update check (pure frontend: hits the public GitHub API, never
 * downloads or installs anything).
 *
 * The channel is injected at build time via vite define into
 * globalThis.__PERSONA_BUILD__ (see vite.config.ts / desktop-build.yml):
 * - nightly daily build: compares the commit and time of the most recent
 *   successful desktop-build.yml run
 * - release: compares against the version of GitHub Releases latest
 * - dev local development: no trustworthy build metadata, never participates
 *   in the comparison
 */

export type UpdateChannel = 'nightly' | 'release' | 'dev';

export interface BuildMeta {
  channel: UpdateChannel;
  /** Commit the build was made from (used for the nightly comparison; empty string for dev/unknown) */
  sha: string;
  /** Build time as an ISO string (used for the nightly comparison; empty string for dev/unknown) */
  builtAt: string;
}

export type UpdateCheckStatus = 'up-to-date' | 'update-available' | 'unavailable';

export interface UpdateCheckResult {
  status: UpdateCheckStatus;
  channel: UpdateChannel;
  /** Current app version (getVersion(); empty string when unavailable) */
  currentVersion: string;
  /** New version identifier: the tag for release (e.g. v0.2.0), a short commit for nightly */
  latestVersion: string | null;
  /** Link to the release page / workflow run page */
  detailUrl: string | null;
  /** Why the check was unavailable */
  reason?: 'no-release' | 'dev-channel' | 'network' | 'no-current-version';
}

export const PERSONA_REPO = 'cuihairu/persona';
const GITHUB_API = `https://api.github.com/repos/${PERSONA_REPO}`;
const FETCH_TIMEOUT_MS = 10_000;

export const UPDATE_CHECK_ENABLED_KEY = 'persona.updateCheck.enabled';
export const UPDATE_CHECK_LAST_KEY = 'persona.updateCheck.lastChecked';

const DEFAULT_BUILD_META: BuildMeta = { channel: 'dev', sha: '', builtAt: '' };

/** Build-time injected metadata; falls back to dev under jest / in environments without the define */
export const getBuildMeta = (): BuildMeta =>
  typeof __PERSONA_BUILD__ === 'undefined' ? DEFAULT_BUILD_META : __PERSONA_BUILD__;

/** Lenient version comparison: compares numeric segments one by one, padding
 * missing segments with 0; returns null when unparsable (the caller treats that
 * as "no update"). */
export const compareVersions = (a: string, b: string): number | null => {
  const toParts = (value: string): number[] | null => {
    const parts = value.replace(/^v/i, '').split('.');
    if (!parts.length) return null;
    const nums = parts.map((part) => Number.parseInt(part, 10));
    if (nums.some((num) => Number.isNaN(num))) return null;
    return nums;
  };
  const pa = toParts(a);
  const pb = toParts(b);
  if (!pa || !pb) return null;
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff > 0 ? 1 : -1;
  }
  return 0;
};

export const isUpdateCheckEnabled = (): boolean => {
  try {
    return window.localStorage.getItem(UPDATE_CHECK_ENABLED_KEY) !== '0';
  } catch {
    return true;
  }
};

export const setUpdateCheckEnabled = (enabled: boolean): void => {
  try {
    window.localStorage.setItem(UPDATE_CHECK_ENABLED_KEY, enabled ? '1' : '0');
  } catch {
    // localStorage unavailable (private mode etc.): the setting is not persisted but stays in effect for this session
  }
};

export const getLastCheckedAt = (): string | null => {
  try {
    return window.localStorage.getItem(UPDATE_CHECK_LAST_KEY);
  } catch {
    return null;
  }
};

export const setLastCheckedAt = (iso: string): void => {
  try {
    window.localStorage.setItem(UPDATE_CHECK_LAST_KEY, iso);
  } catch {
    // Same as above: not persisting is not fatal
  }
};

const currentAppVersion = async (): Promise<string> => {
  try {
    return (await getVersion()) || '';
  } catch {
    // Non-Tauri environment (jest / plain vite dev)
    return '';
  }
};

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

/** Returns the parsed JSON; 404 → null (the caller reports "nothing on the channel yet"); other non-2xx responses throw */
const fetchJson = async (fetchFn: FetchLike, url: string): Promise<unknown | null> => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetchFn(url, {
      headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
      signal: controller.signal,
    });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`GitHub API ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
};

interface ReleasePayload {
  tag_name?: string;
  html_url?: string;
}

interface WorkflowRunsPayload {
  workflow_runs?: Array<{
    head_sha?: string;
    created_at?: string;
    html_url?: string;
  }>;
}

/**
 * Checks for updates per build channel. Network and API errors are always
 * converted to `unavailable` and never thrown to the caller — a failed check
 * must not interrupt the usage flow.
 */
export const checkForUpdate = async (
  deps: { fetchFn?: FetchLike } = {},
): Promise<UpdateCheckResult> => {
  const meta = getBuildMeta();
  const fetchFn = deps.fetchFn ?? ((url: string, init?: RequestInit) => fetch(url, init));
  const currentVersion = await currentAppVersion();
  const base: Omit<UpdateCheckResult, 'status' | 'latestVersion' | 'detailUrl' | 'reason'> = {
    channel: meta.channel,
    currentVersion,
  };

  if (meta.channel === 'dev') {
    return { ...base, status: 'unavailable', latestVersion: null, detailUrl: null, reason: 'dev-channel' };
  }

  try {
    if (meta.channel === 'release') {
      if (!currentVersion) {
        return { ...base, status: 'unavailable', latestVersion: null, detailUrl: null, reason: 'no-current-version' };
      }
      const release = (await fetchJson(fetchFn, `${GITHUB_API}/releases/latest`)) as ReleasePayload | null;
      if (!release?.tag_name) {
        return { ...base, status: 'unavailable', latestVersion: null, detailUrl: null, reason: 'no-release' };
      }
      const cmp = compareVersions(release.tag_name, currentVersion);
      const newer = cmp !== null && cmp > 0;
      return {
        ...base,
        status: newer ? 'update-available' : 'up-to-date',
        latestVersion: release.tag_name,
        detailUrl: release.html_url ?? `https://github.com/${PERSONA_REPO}/releases/latest`,
      };
    }

    // nightly: the most recent successful desktop-build run is the "daily update source"
    const data = (await fetchJson(
      fetchFn,
      `${GITHUB_API}/actions/workflows/desktop-build.yml/runs?status=success&per_page=5`,
    )) as WorkflowRunsPayload | null;
    const run = data?.workflow_runs?.[0];
    if (!run?.head_sha || !run.created_at) {
      return { ...base, status: 'unavailable', latestVersion: null, detailUrl: null, reason: 'no-release' };
    }
    const runTime = Date.parse(run.created_at);
    const buildTime = Date.parse(meta.builtAt);
    // A different commit is the only evidence of a new build; when both times are missing, conservatively treat it as newer (better to over-prompt than to miss)
    const newer =
      run.head_sha !== meta.sha &&
      (Number.isNaN(buildTime) || Number.isNaN(runTime) || runTime > buildTime);
    return {
      ...base,
      status: newer ? 'update-available' : 'up-to-date',
      latestVersion: run.head_sha.slice(0, 7),
      detailUrl: run.html_url ?? `https://github.com/${PERSONA_REPO}/actions/workflows/desktop-build.yml`,
    };
  } catch {
    return { ...base, status: 'unavailable', latestVersion: null, detailUrl: null, reason: 'network' };
  }
};
