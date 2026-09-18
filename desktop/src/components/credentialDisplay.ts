import {
  KeyIcon,
  WalletIcon,
  ServerIcon,
  CreditCardIcon,
  ShieldCheckIcon,
} from '@heroicons/react/24/outline';

/**
 * 列表行与详情面板共用的展示 helper（叶子模块，避免两者互相引用）。
 */

/** 凭据类型 → 图标组件 */
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
    case 'ApiKey':
    case 'Certificate':
    case 'TwoFactor':
    default:
      return ShieldCheckIcon;
  }
};

/** 安全等级 → 五档配色（未知档走 default 灰） */
export const getSecurityColor = (level: string) => {
  switch (level) {
    case 'Critical':
      return 'bg-red-100 text-red-800 border-red-200';
    case 'High':
      return 'bg-orange-100 text-orange-800 border-orange-200';
    case 'Medium':
      return 'bg-yellow-100 text-yellow-800 border-yellow-200';
    case 'Low':
      return 'bg-green-100 text-green-800 border-green-200';
    default:
      return 'bg-gray-100 text-gray-800 border-gray-200';
  }
};

/** URL → hostname（解析失败原样回显） */
export const getSafeHostname = (url: string) => {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
};
