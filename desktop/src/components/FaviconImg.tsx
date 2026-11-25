import React, { useState } from 'react';
import { useAppStore } from '@/stores/appStore';
import { getFaviconCacheKey } from '@/components/credentialDisplay';

interface FaviconImgProps {
  /** Credential URL (optional; a missing url or a disabled flag always renders the static icon) */
  url?: string | null;
  fallbackIcon: React.ComponentType<{ className?: string }>;
  sizeClass?: string;
  className?: string;
}

/**
 * Three-state favicon convergence: flag on and a cache hit and not broken →
 * <img data: URL>; flag off / cache miss / broken via onError → the static
 * fallback icon. The component only reads the cache and never triggers IPC
 * (prefetching is the caller's useFavicons job).
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
