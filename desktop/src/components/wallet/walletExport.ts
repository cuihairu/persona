import type { WalletSummary } from '@/types';

export type WalletExportFormat = 'json' | 'xpub' | 'mnemonic' | 'private_key' | 'wif' | 'keystore';

type Translate = (key: string) => string;

export const formatLabel = (t: Translate, format: WalletExportFormat): string => {
  switch (format) {
    case 'json':
      return 'JSON';
    case 'xpub':
      return 'XPUB';
    case 'mnemonic':
      return t('wallet.importMnemonic');
    case 'private_key':
      return t('wallet.importPrivateKey');
    case 'wif':
      return 'Bitcoin WIF';
    case 'keystore':
      return 'Ethereum keystore v3';
  }
};

export const getAvailableExportFormats = (wallet: WalletSummary | null): WalletExportFormat[] => {
  if (!wallet) {
    return ['json'];
  }

  const formats: WalletExportFormat[] = ['json'];

  if (wallet.wallet_type.includes('HierarchicalDeterministic') || wallet.wallet_type.includes('HD')) {
    formats.push('xpub');
  }

  if (!wallet.watch_only) {
    formats.push('private_key');
  }

  if (!wallet.watch_only && wallet.wallet_type.includes('HierarchicalDeterministic')) {
    formats.push('mnemonic');
  }

  if (!wallet.watch_only && wallet.network.toLowerCase() === 'bitcoin' && wallet.wallet_type === 'SingleAddress') {
    formats.push('wif');
  }

  // Web3 Secret Storage v3 is defined over secp256k1 keys: Ethereum only
  if (!wallet.watch_only && wallet.network.toLowerCase() === 'ethereum') {
    formats.push('keystore');
  }

  return formats;
};

export const getExportRestrictionHint = (
  t: Translate,
  wallet: WalletSummary | null,
  format: WalletExportFormat,
): string | null => {
  if (!wallet || format !== 'json') {
    return null;
  }

  if (wallet.watch_only) {
    return t('wallet.restrictions.watchOnly');
  }

  if (wallet.wallet_type === 'SingleAddress' && wallet.network.toLowerCase() === 'bitcoin') {
    return t('wallet.restrictions.btcSingle');
  }

  return null;
};
