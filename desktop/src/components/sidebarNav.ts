import {
  BanknotesIcon,
  BriefcaseIcon,
  ChartBarIcon,
  ClockIcon,
  CodeBracketIcon,
  ComputerDesktopIcon,
  CreditCardIcon,
  DevicePhoneMobileIcon,
  DocumentTextIcon,
  FingerPrintIcon,
  HeartIcon,
  HomeIcon,
  IdentificationIcon,
  KeyIcon,
  PuzzlePieceIcon,
  ServerIcon,
  ShieldExclamationIcon,
  SparklesIcon,
  Squares2X2Icon,
  UserCircleIcon,
  UserGroupIcon,
  WalletIcon,
} from '@heroicons/react/24/outline';
import type { TFunction } from 'i18next';
import type { CredentialCategory, FeatureFlags, Identity, SidebarFilter } from '@/types';

export type { SidebarFilter };

/**
 * Single source of truth for sidebar navigation: node definitions, the
 * category↔credential-type mapping, filter-state↔main-area-view mapping, and
 * display-name resolution. Sidebar rendering, App's derived main-area view and
 * title, and CredentialList's derived list filters all read from here, so the
 * three don't each keep their own copy of labels and flag checks.
 */

/** Main-area views: 'credentials' is the list; the rest are tool/admin panels */
export type ViewId =
  | 'credentials'
  | 'statistics'
  | 'sshAgent'
  | 'wallets'
  | 'watchtower'
  | 'passkeys'
  | 'generator';

type IconComponent = typeof Squares2X2Icon;

/** Identity (vault) type → icon; one mapping shared by IdentitySwitcher and the sidebar vault rows */
export const identityIcon = (identityType: string): IconComponent => {
  switch (identityType) {
    case 'Personal':
      return HomeIcon;
    case 'Work':
      return BriefcaseIcon;
    case 'Social':
      return UserGroupIcon;
    case 'Financial':
      return CreditCardIcon;
    case 'Gaming':
      return PuzzlePieceIcon;
    default:
      return UserCircleIcon;
  }
};

export interface NavNode {
  /** Filter state written to the store when clicked */
  filter: SidebarFilter;
  /** i18n key (nodes are module-level constants, so no hooks—t() at the render site) */
  labelKey: string;
  icon: IconComponent;
  /** Corresponding workspace feature flag; omitted = mainline, always visible */
  flag?: keyof FeatureFlags;
  /** Category-only: the aggregated credential_types (used for list filtering) */
  types?: string[];
}

/** Sidebar default filter state (the store's factory value, see appStore.DEFAULT_SIDEBAR_FILTER) */
export const ALL_ITEMS_FILTER: SidebarFilter = { kind: 'all' };

/** Category → credential types (1Password's category semantics: one category aggregates several item types) */
export const CATEGORY_TYPES: Record<CredentialCategory, string[]> = {
  passwords: ['Password'],
  secure_notes: ['SecureNote'],
  api_keys: ['ApiKey', 'Certificate'],
  ssh_keys: ['SshKey', 'ServerConfig'],
  software_licenses: ['SoftwareLicense'],
  identity_documents: ['Identity', 'BankCard'],
  crypto_wallets: ['CryptoWallet'],
  game_tokens: ['TwoFactor', 'GameToken', 'GameAccount'],
};

/** Top three rows: All Items / Favorites / Recently Used */
export const TOP_NODES: NavNode[] = [
  { filter: ALL_ITEMS_FILTER, labelKey: 'sidebar.allItems', icon: Squares2X2Icon },
  { filter: { kind: 'favorites' }, labelKey: 'sidebar.favorites', icon: HeartIcon },
  { filter: { kind: 'recent' }, labelKey: 'sidebar.recent', icon: ClockIcon },
];

/**
 * Category group. Passkeys are the special case: they live in a separate
 * passkeys table and never enter the credential list, so that row does not
 * produce { kind: 'category' } but opens the admin view instead.
 */
export const CATEGORY_NODES: NavNode[] = [
  {
    filter: { kind: 'category', value: 'passwords' },
    labelKey: 'sidebar.category.passwords',
    icon: KeyIcon,
    types: CATEGORY_TYPES.passwords,
  },
  {
    filter: { kind: 'passkeys' },
    labelKey: 'sidebar.category.passkeys',
    icon: FingerPrintIcon,
    flag: 'passkeys',
  },
  {
    filter: { kind: 'category', value: 'secure_notes' },
    labelKey: 'sidebar.category.secureNotes',
    icon: DocumentTextIcon,
    types: CATEGORY_TYPES.secure_notes,
  },
  {
    filter: { kind: 'category', value: 'api_keys' },
    labelKey: 'sidebar.category.apiKeys',
    icon: CodeBracketIcon,
    types: CATEGORY_TYPES.api_keys,
  },
  {
    filter: { kind: 'category', value: 'ssh_keys' },
    labelKey: 'sidebar.category.sshKeys',
    icon: ComputerDesktopIcon,
    flag: 'ssh_agent',
    types: CATEGORY_TYPES.ssh_keys,
  },
  {
    filter: { kind: 'category', value: 'software_licenses' },
    labelKey: 'sidebar.category.softwareLicenses',
    icon: CreditCardIcon,
    types: CATEGORY_TYPES.software_licenses,
  },
  {
    filter: { kind: 'category', value: 'identity_documents' },
    labelKey: 'sidebar.category.identityDocuments',
    icon: IdentificationIcon,
    types: CATEGORY_TYPES.identity_documents,
  },
  {
    filter: { kind: 'category', value: 'crypto_wallets' },
    labelKey: 'sidebar.category.cryptoWallets',
    icon: WalletIcon,
    types: CATEGORY_TYPES.crypto_wallets,
  },
  {
    filter: { kind: 'category', value: 'game_tokens' },
    labelKey: 'sidebar.category.gameTokens',
    icon: DevicePhoneMobileIcon,
    types: CATEGORY_TYPES.game_tokens,
  },
];

/** Tools group: panel views (Statistics / SSH Agent / Wallets / Watchtower / Generator) */
export const TOOL_NODES: NavNode[] = [
  { filter: { kind: 'statistics' }, labelKey: 'sidebar.tools.statistics', icon: ChartBarIcon },
  {
    filter: { kind: 'sshAgent' },
    labelKey: 'sidebar.tools.sshAgent',
    icon: ServerIcon,
    flag: 'ssh_agent',
  },
  { filter: { kind: 'wallets' }, labelKey: 'sidebar.tools.wallets', icon: BanknotesIcon, flag: 'wallet' },
  {
    filter: { kind: 'watchtower' },
    labelKey: 'sidebar.tools.watchtower',
    icon: ShieldExclamationIcon,
  },
  { filter: { kind: 'generator' }, labelKey: 'sidebar.tools.generator', icon: SparklesIcon },
];

/** Filter state → main-area view (everything except tools/passkeys is the credential list) */
export const viewForFilter = (filter: SidebarFilter): ViewId => {
  switch (filter.kind) {
    case 'statistics':
      return 'statistics';
    case 'sshAgent':
      return 'sshAgent';
    case 'wallets':
      return 'wallets';
    case 'watchtower':
      return 'watchtower';
    case 'passkeys':
      return 'passkeys';
    case 'generator':
      return 'generator';
    default:
      return 'credentials';
  }
};

/** View → the feature flag it depends on (when the flag is turned off at runtime, fall back to the credential list accordingly) */
export const FLAG_BY_VIEW: Partial<Record<ViewId, keyof FeatureFlags>> = {
  sshAgent: 'ssh_agent',
  wallets: 'wallet',
  passkeys: 'passkeys',
};

/** testid for sidebar rows / test anchors: nav-all, nav-category-api_keys, nav-identity-i1... */
export const navTestId = (filter: SidebarFilter): string => {
  const value = 'value' in filter ? filter.value : undefined;
  return `nav-${filter.kind}${value ? `-${value}` : ''}`;
};

/** Whether two filter states point at the same node (missing value is always compared as no value) */
export const isSameFilter = (a: SidebarFilter, b: SidebarFilter): boolean => {
  if (a.kind !== b.kind) return false;
  return ('value' in a ? a.value : undefined) === ('value' in b ? b.value : undefined);
};

/**
 * Display name for a filter state (shared by the main-area toolbar title and
 * empty-state hints): a node uses its own labelKey, a tag uses `#tag`, a vault
 * uses the identity name (falls back to All Items when not found).
 */
export const filterLabel = (
  t: TFunction,
  filter: SidebarFilter,
  identities: Identity[] = [],
): string => {
  switch (filter.kind) {
    case 'all':
      return t('sidebar.allItems');
    case 'favorites':
      return t('sidebar.favorites');
    case 'recent':
      return t('sidebar.recent');
    case 'tag':
      return `#${filter.value}`;
    case 'identity':
      return identities.find((i) => i.id === filter.value)?.name ?? t('sidebar.allItems');
    case 'category': {
      // The node table is the source of truth for labelKey (the i18n key is
      // camelCase while the filter value is snake_case, so they cannot be
      // concatenated directly); fall back to All Items when not found
      const node = CATEGORY_NODES.find(
        (n) => n.filter.kind === 'category' && n.filter.value === filter.value,
      );
      return node ? t(node.labelKey) : t('sidebar.allItems');
    }
    default: {
      const node = [...TOOL_NODES, ...CATEGORY_NODES].find((n) => n.filter.kind === filter.kind);
      return node ? t(node.labelKey) : t('sidebar.allItems');
    }
  }
};
