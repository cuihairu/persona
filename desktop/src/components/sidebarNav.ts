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
 * 侧栏导航的单一事实源：节点定义、分类↔凭据类型映射、筛选态↔主区视图映射、
 * 显示名解析。Sidebar 渲染、App 派生主区视图与标题、CredentialList 派生
 * 列表筛选都从这里取，避免三处各写一份标签与开关判断。
 */

/** 主区视图：'credentials' 是列表，其余是工具/管理面板 */
export type ViewId =
  | 'credentials'
  | 'statistics'
  | 'sshAgent'
  | 'wallets'
  | 'watchtower'
  | 'passkeys'
  | 'generator';

type IconComponent = typeof Squares2X2Icon;

/** 身份（保险库）类型 → 图标；IdentitySwitcher 与侧栏保险库行共用一份映射 */
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
  /** 点击后写入 store 的筛选态 */
  filter: SidebarFilter;
  /** i18n key（节点是模块级常量，不能调 hook，渲染处 t()） */
  labelKey: string;
  icon: IconComponent;
  /** 对应 workspace 功能开关；缺省 = 主航道，恒可见 */
  flag?: keyof FeatureFlags;
  /** 分类专用：聚合的 credential_type（列表筛选用） */
  types?: string[];
}

/** 侧栏默认筛选态（store 出厂值，见 appStore.DEFAULT_SIDEBAR_FILTER） */
export const ALL_ITEMS_FILTER: SidebarFilter = { kind: 'all' };

/** 分类 → 凭据类型（1Password 的类别语义：一个类别聚合多种 item type） */
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

/** 顶部三行：全部条目 / 收藏 / 最近使用 */
export const TOP_NODES: NavNode[] = [
  { filter: ALL_ITEMS_FILTER, labelKey: 'sidebar.allItems', icon: Squares2X2Icon },
  { filter: { kind: 'favorites' }, labelKey: 'sidebar.favorites', icon: HeartIcon },
  { filter: { kind: 'recent' }, labelKey: 'sidebar.recent', icon: ClockIcon },
];

/**
 * 类别分组。通行密钥是特例：它存在独立 passkeys 表里、不进凭据列表，
 * 所以这一行不产出 { kind: 'category' } 而是打开管理视图。
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

/** 工具分组：面板视图（统计 / SSH Agent / 钱包 / 安全瞭望 / 生成器） */
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

/** 筛选态 → 主区视图（除工具/通行密钥外都是凭据列表） */
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

/** 视图 → 依赖的功能开关（运行中关掉开关时据此回落到凭据列表） */
export const FLAG_BY_VIEW: Partial<Record<ViewId, keyof FeatureFlags>> = {
  sshAgent: 'ssh_agent',
  wallets: 'wallet',
  passkeys: 'passkeys',
};

/** 侧栏行 / 测试锚点的 testid：nav-all、nav-category-api_keys、nav-identity-i1… */
export const navTestId = (filter: SidebarFilter): string => {
  const value = 'value' in filter ? filter.value : undefined;
  return `nav-${filter.kind}${value ? `-${value}` : ''}`;
};

/** 两个筛选态是否指向同一节点（value 缺省的一律按无值比较） */
export const isSameFilter = (a: SidebarFilter, b: SidebarFilter): boolean => {
  if (a.kind !== b.kind) return false;
  return ('value' in a ? a.value : undefined) === ('value' in b ? b.value : undefined);
};

/**
 * 筛选态的显示名（主区工具条标题与空态提示共用）：
 * 节点取自身 labelKey，标签取 `#tag`，保险库取身份名（找不到回退全部条目）。
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
      // 节点表是 labelKey 的事实源（i18n key 是驼峰，筛选值是 snake_case，
      // 不能直接拼接）；查不到回退全部条目
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
