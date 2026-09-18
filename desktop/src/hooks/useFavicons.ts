import { useEffect, useMemo } from 'react';
import { personaAPI } from '@/utils/api';
import { useAppStore } from '@/stores/appStore';
import type { FaviconEntry } from '@/stores/appStore';
import { getFaviconCacheKey } from '@/components/credentialDisplay';

/**
 * 模块级并发去重：同 host 的批量读进行中时不重复发 IPC。
 * jest 内用 __resetFaviconInFlight 重置（模块状态在测试文件间不共享，
 * 同文件内用例会残留）。
 */
const inFlight = new Map<string, Promise<void>>();

/** 测试专用：清空并发去重表（仅测试文件使用） */
export const __resetFaviconInFlight = () => {
  inFlight.clear();
};

/**
 * favicon 批量预取（纯缓存读，绝不触发抓取——唯一外联入口是详情面板
 * "Fetch icon" 按钮）：flag 开时对既不在缓存也不在负缓存的 host 批量
 * getFavicons，命中的并入缓存、缺席的落负缓存（失败不落，依赖变化
 * 自然重试）。返回 faviconFor(url)：flag 关恒 null。
 */
export const useFavicons = (urls: (string | null | undefined)[]) => {
  const flagEnabled = useAppStore((s) => s.featureFlags.fetch_favicons);
  const faviconCache = useAppStore((s) => s.faviconCache);
  const faviconMisses = useAppStore((s) => s.faviconMisses);
  const setFaviconEntries = useAppStore((s) => s.setFaviconEntries);
  const setFaviconMisses = useAppStore((s) => s.setFaviconMisses);

  // urls 数组每次渲染都是新引用——依赖 join 后的稳定字符串
  const urlsKey = urls.join('\n');
  const hosts = useMemo(
    () =>
      Array.from(
        new Set(
          urlsKey
            .split('\n')
            .filter(Boolean)
            .map((u) => getFaviconCacheKey(u))
            .filter(Boolean),
        ),
      ).sort(),
    [urlsKey],
  );

  const cacheKey = Object.keys(faviconCache).length;
  const missesKey = Object.keys(faviconMisses).length;

  useEffect(() => {
    if (!flagEnabled || hosts.length === 0) return;

    const pending = hosts.filter(
      (h) =>
        !(h in faviconCache) && !(h in faviconMisses) && !inFlight.has(h),
    );
    if (pending.length === 0) return;

    const promise = (async () => {
      try {
        const resp = await personaAPI.getFavicons(pending);
        if (resp.success && resp.data) {
          setFaviconEntries(resp.data);
          const returned = new Set(resp.data.map((d) => d.host));
          const missed = pending.filter((h) => !returned.has(h));
          if (missed.length > 0) setFaviconMisses(missed);
        }
      } catch {
        // 请求失败不标 miss：保持"未决"状态，缓存/开关变化时自然重试
      } finally {
        for (const h of pending) inFlight.delete(h);
      }
    })();
    for (const h of pending) inFlight.set(h, promise);
  }, [flagEnabled, hosts, cacheKey, missesKey]);

  const faviconFor = (url: string | null | undefined): FaviconEntry | null => {
    if (!flagEnabled || !url) return null;
    return faviconCache[getFaviconCacheKey(url)] ?? null;
  };

  return { faviconFor };
};
