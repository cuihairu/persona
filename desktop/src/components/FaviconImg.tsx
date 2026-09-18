import React, { useState } from 'react';
import { useAppStore } from '@/stores/appStore';
import { getFaviconCacheKey } from '@/components/credentialDisplay';

interface FaviconImgProps {
  /** 凭据 URL（可选；缺省或 flag 关一律渲染静态图标） */
  url?: string | null;
  fallbackIcon: React.ComponentType<{ className?: string }>;
  sizeClass?: string;
  className?: string;
}

/**
 * favicon 三态收口：flag 开且缓存命中且未破图 → <img data: URL>；
 * flag 关 / 缓存 miss / onError 破图 → 静态 fallback 图标。
 * 组件只查缓存，不触发任何 IPC（预取由调用方的 useFavicons 负责）。
 */
const FaviconImg: React.FC<FaviconImgProps> = ({
  url,
  fallbackIcon: Icon,
  sizeClass = 'w-5 h-5',
  className = '',
}) => {
  const flagEnabled = useAppStore((s) => s.featureFlags.fetch_favicons);
  const faviconCache = useAppStore((s) => s.faviconCache);
  const [broken, setBroken] = useState(false);

  const entry = flagEnabled && url ? faviconCache[getFaviconCacheKey(url)] : undefined;
  if (!entry || broken) {
    return <Icon className={`${sizeClass} shrink-0 ${className}`} />;
  }
  return (
    <img
      src={`data:${entry.mime_type};base64,${entry.data}`}
      alt=""
      draggable={false}
      onError={() => setBroken(true)}
      data-testid="favicon-img"
      className={`${sizeClass} shrink-0 rounded-sm object-contain ${className}`}
    />
  );
};

export default FaviconImg;
