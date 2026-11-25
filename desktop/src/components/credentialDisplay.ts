import {
  KeyIcon,
  WalletIcon,
  ServerIcon,
  CreditCardIcon,
  ShieldCheckIcon,
  UserIcon,
  DocumentTextIcon,
} from '@heroicons/react/24/outline';
import type { TFunction } from 'i18next';

/**
 * Display helpers shared by the list rows and the detail panel (leaf module so
 * the two never import each other).
 */

/** Credential type → icon component */
export const getCredentialIcon = (type: string) => {
  switch (type) {
    case 'Password':
      return KeyIcon;
    case 'CryptoWallet':
      return WalletIcon;
    case 'SshKey':
    case 'ServerConfig':
      return ServerIcon;
    case 'BankCard':
      return CreditCardIcon;
    case 'Identity':
      return UserIcon;
    case 'SoftwareLicense':
      return DocumentTextIcon;
    case 'ApiKey':
    case 'Certificate':
    case 'TwoFactor':
    default:
      return ShieldCheckIcon;
  }
};

/** Security level → five-tier color scheme (unknown tier falls to the default gray) */
export const getSecurityColor = (level: string) => {
  switch (level) {
    case 'Critical':
      return 'bg-red-100 dark:bg-red-500/10 text-red-800 dark:text-red-300 border-red-200 dark:border-red-500/20';
    case 'High':
      return 'bg-orange-100 dark:bg-orange-500/10 text-orange-800 dark:text-orange-300 border-orange-200 dark:border-orange-500/20';
    case 'Medium':
      return 'bg-yellow-100 dark:bg-yellow-500/10 text-yellow-800 dark:text-yellow-300 border-yellow-200 dark:border-yellow-500/20';
    case 'Low':
      return 'bg-green-100 dark:bg-green-500/10 text-green-800 dark:text-green-300 border-green-200 dark:border-green-500/20';
    default:
      return 'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200 border-gray-200 dark:border-gray-700';
  }
};

/** URL → hostname (echoes the raw input when parsing fails) */
export const getSafeHostname = (url: string) => {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
};

/**
 * URL → favicon cache key (shared by the useFavicons batch read and
 * FaviconImg's cache lookup, so both sides hit the same key; may diverge in
 * edge cases from the backend's extract_favicon_host normalization — this
 * only causes a cache key miss and a fallback to the static icon, harmless).
 */
export const getFaviconCacheKey = (url: string) =>
  getSafeHostname(url).trim().toLowerCase();

/** Credential type display name (unknown types fall back to the raw value) */
export const credentialTypeLabel = (t: TFunction, type: string) =>
  t(`credentialTypes.${type}`, { defaultValue: type });

/** Security level display name (unknown levels fall back to the raw value) */
export const securityLevelLabel = (t: TFunction, level: string) =>
  t(`securityLevels.${level}`, { defaultValue: level });
