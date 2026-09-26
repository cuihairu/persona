import { getVersion } from '@tauri-apps/api/app';

/**
 * 桌面端版本更新检测（纯前端：访问 GitHub 公开 API，不下载不安装）。
 *
 * 渠道在构建期经 vite define 注入 globalThis.__PERSONA_BUILD__
 * （见 vite.config.ts / desktop-build.yml）：
 * - nightly 每日构建：比对 desktop-build.yml 最近一次成功 run 的 commit 与时间
 * - release 正式版：比对 GitHub Releases latest 的版本号
 * - dev 本地开发：没有可信构建元信息，不参与比对
 */

export type UpdateChannel = 'nightly' | 'release' | 'dev';

export interface BuildMeta {
  channel: UpdateChannel;
  /** 构建所在 commit（nightly 比对用；dev/未知为空串） */
  sha: string;
  /** 构建时间 ISO 串（nightly 比对用；dev/未知为空串） */
  builtAt: string;
}

export type UpdateCheckStatus = 'up-to-date' | 'update-available' | 'unavailable';

export interface UpdateCheckResult {
  status: UpdateCheckStatus;
  channel: UpdateChannel;
  /** 当前应用版本（getVersion()；读不到为空串） */
  currentVersion: string;
  /** 新版本标识：release 为 tag（如 v0.2.0），nightly 为短 commit */
  latestVersion: string | null;
  /** release 页 / workflow run 页链接 */
  detailUrl: string | null;
  /** unavailable 时的原因 */
  reason?: 'no-release' | 'dev-channel' | 'network' | 'no-current-version';
}

export const PERSONA_REPO = 'cuihairu/persona';
const GITHUB_API = `https://api.github.com/repos/${PERSONA_REPO}`;
const FETCH_TIMEOUT_MS = 10_000;

export const UPDATE_CHECK_ENABLED_KEY = 'persona.updateCheck.enabled';
export const UPDATE_CHECK_LAST_KEY = 'persona.updateCheck.lastChecked';

const DEFAULT_BUILD_META: BuildMeta = { channel: 'dev', sha: '', builtAt: '' };

/** 构建期注入的元信息；jest / 无 define 环境回退 dev */
export const getBuildMeta = (): BuildMeta =>
  typeof __PERSONA_BUILD__ === 'undefined' ? DEFAULT_BUILD_META : __PERSONA_BUILD__;

/** 宽松版本号比较：按数字段逐段比，段数不足补 0；解析不了返回 null（调用方当作"不更新"） */
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
    // localStorage 不可用（隐私模式等）：设置不持久化，本次会话仍生效
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
    // 同上：不持久化不致命
  }
};

const currentAppVersion = async (): Promise<string> => {
  try {
    return (await getVersion()) || '';
  } catch {
    // 非 Tauri 环境（jest / 纯 vite dev）
    return '';
  }
};

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

/** 返回解析后的 JSON；404 → null（调用方表示"渠道上还没有东西"）；其余非 2xx 抛错 */
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
 * 按构建渠道检查更新。网络与接口错误一律折算成 `unavailable`，
 * 不向调用方抛异常——检查失败不该打断使用流程。
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

    // nightly：最近一次成功的 desktop-build run 就是"每日更新源"
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
    // commit 不同才算有新版；时间都缺时保守当作有新版（宁可提示不漏报）
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
