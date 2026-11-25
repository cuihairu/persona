import { useEffect, useMemo } from 'react';
import { personaAPI } from '@/utils/api';
import { useAppStore } from '@/stores/appStore';
import type { FaviconEntry } from '@/stores/appStore';
import { getFaviconCacheKey } from '@/components/credentialDisplay';

/**
 * Module-level in-flight dedup: no duplicate IPC while a batched read for the
 * same host is already running. Jest resets it via __resetFaviconInFlight
 * (module state is not shared across test files, and cases within one file
 * would otherwise leak into each other).
 */
const inFlight = new Map<string, Promise<void>>();

/** Test-only: clear the in-flight dedup table (used only by test files) */
export const __resetFaviconInFlight = () => {
  inFlight.clear();
};

/**
 * Batched favicon prefetch (pure cache reads, never triggers a fetch — the only
 * outbound path is the detail pane's "Fetch icon" button): when the flag is on,
 * batch getFavicons for hosts that are in neither the cache nor the negative
 * cache; hits merge into the cache and absences fall into the negative cache
 * (failures do not land there, so a dependency change retries naturally).
 * Returns faviconFor(url): always null when the flag is off.
 */
export const useFavicons = (urls: (string | null | undefined)[]) => {
  const flagEnabled = useAppStore((s) => s.featureFlags.fetch_favicons);
  const faviconCache = useAppStore((s) => s.faviconCache);
  const faviconMisses = useAppStore((s) => s.faviconMisses);
  const setFaviconEntries = useAppStore((s) => s.setFaviconEntries);
  const setFaviconMisses = useAppStore((s) => s.setFaviconMisses);

  // The urls array is a fresh reference every render — depend on the stable string after join
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
        // A failed request is not marked as a miss: keep the "pending" state so a cache/flag change retries naturally
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
