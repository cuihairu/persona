import type { CredentialDataRequest, CredentialType, SecurityLevel } from '@/types';

// Encodes the payload by type on submit; option constants for the type/grade dropdowns (matching the CLI-side
// convention: GameToken hangs off the TwoFactor type at creation).
  export const CREDENTIAL_TYPE_OPTIONS: CredentialType[] = [
    'Password',
    'CryptoWallet',
    'SshKey',
    'ApiKey',
    'BankCard',
    'ServerConfig',
    'Certificate',
    'TwoFactor',
    'GameToken',
    'SecureNote',
    'Identity',
    'SoftwareLicense',
  ];

  export const SECURITY_LEVEL_OPTIONS: SecurityLevel[] = ['Critical', 'High', 'Medium', 'Low'];

export const parseOtpauthUri = (uri: string) => {
  try {
    const url = new URL(uri);
    if (url.protocol !== 'otpauth:' || url.hostname !== 'totp') return null;

    const secret = url.searchParams.get('secret') || '';
    const issuer = url.searchParams.get('issuer') || '';
    const algorithm = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase();
    const digits = Number(url.searchParams.get('digits') || '6');
    const period = Number(url.searchParams.get('period') || '30');

    const rawLabel = decodeURIComponent(url.pathname.replace(/^\//, ''));
    const labelParts = rawLabel.split(':');
    const accountFromLabel = labelParts.length > 1 ? labelParts.slice(1).join(':') : rawLabel;
    const issuerFromLabel = labelParts.length > 1 ? labelParts[0] : '';

    return {
      secret_key: secret,
      issuer: issuer || issuerFromLabel,
      account_name: url.searchParams.get('account') || accountFromLabel,
      algorithm,
      digits: Number.isFinite(digits) ? digits : 6,
      period: Number.isFinite(period) ? period : 30,
    };
  } catch {
    return null;
  }
};

/** Form state -> CredentialDataRequest (pure encoding, no request issued; the trim/default conventions are per branch). */
export const buildCredentialDataRequest = (
  credentialType: CredentialType,
  credentialData: any,
  url: string,
): CredentialDataRequest => {
  let credentialDataRequest: CredentialDataRequest;

  switch (credentialType) {
  case 'Password':
    credentialDataRequest = {
      type: 'Password',
      password: credentialData.password,
      email: credentialData.email || undefined,
      security_questions: credentialData.security_questions || [],
    };
    break;

  case 'TwoFactor':
    credentialDataRequest = {
      type: 'TwoFactor',
      secret_key: (credentialData.secret_key || '').trim(),
      issuer: (credentialData.issuer || '').trim(),
      account_name: (credentialData.account_name || '').trim(),
      algorithm: (credentialData.algorithm || 'SHA1').toString(),
      digits: Number(credentialData.digits || 6),
      period: Number(credentialData.period || 30),
    };
    break;

  case 'GameToken':
    credentialDataRequest = {
      type: 'GameToken',
      provider: (credentialData.provider || '').trim().toLowerCase(),
      secret_key: (credentialData.secret_key || '').trim(),
      issuer: (credentialData.issuer || '').trim(),
      account_name: (credentialData.account_name || '').trim(),
      url: url.trim() || undefined,
    };
    break;

  case 'SecureNote':
    credentialDataRequest = {
      type: 'SecureNote',
      note: credentialData.note || '',
    };
    break;

  case 'Identity':
    credentialDataRequest = {
      type: 'Identity',
      first_name: (credentialData.first_name || '').trim(),
      last_name: (credentialData.last_name || '').trim(),
      username: (credentialData.username || '').trim() || undefined,
      email: (credentialData.email || '').trim() || undefined,
      phone: (credentialData.phone || '').trim() || undefined,
      birthday: (credentialData.birthday || '').trim() || undefined,
      address: (credentialData.address || '').trim() || undefined,
      id_number: (credentialData.id_number || '').trim() || undefined,
      passport_number: (credentialData.passport_number || '').trim() || undefined,
      driver_license: (credentialData.driver_license || '').trim() || undefined,
      tax_id: (credentialData.tax_id || '').trim() || undefined,
      organization: (credentialData.organization || '').trim() || undefined,
      job_title: (credentialData.job_title || '').trim() || undefined,
    };
    break;

  case 'SoftwareLicense':
    credentialDataRequest = {
      type: 'SoftwareLicense',
      license_key: (credentialData.license_key || '').trim(),
      version: (credentialData.version || '').trim() || undefined,
      publisher: (credentialData.publisher || '').trim() || undefined,
      purchase_date: (credentialData.purchase_date || '').trim() || undefined,
      order_number: (credentialData.order_number || '').trim() || undefined,
      support_email: (credentialData.support_email || '').trim() || undefined,
      download_url: (credentialData.download_url || '').trim() || undefined,
      seats: credentialData.seats ? Number(credentialData.seats) : undefined,
      valid_until: (credentialData.valid_until || '').trim() || undefined,
    };
    break;

  case 'CryptoWallet':
    credentialDataRequest = {
      type: 'CryptoWallet',
      wallet_type: credentialData.wallet_type || 'Bitcoin',
      mnemonic_phrase: credentialData.mnemonic_phrase || undefined,
      private_key: credentialData.private_key || undefined,
      public_key: credentialData.public_key || '',
      address: credentialData.address || '',
      network: credentialData.network || 'mainnet',
      bip39_passphrase: credentialData.bip39_passphrase || undefined,
    };
    break;

  case 'SshKey':
    credentialDataRequest = {
      type: 'SshKey',
      private_key: credentialData.private_key || '',
      public_key: credentialData.public_key || '',
      key_type: credentialData.key_type || 'rsa',
      passphrase: credentialData.passphrase || undefined,
    };
    break;

  case 'ApiKey':
    credentialDataRequest = {
      type: 'ApiKey',
      api_key: credentialData.api_key || '',
      api_secret: credentialData.api_secret || undefined,
      token: credentialData.token || undefined,
      permissions: credentialData.permissions || [],
      expires_at: credentialData.expires_at || undefined,
    };
    break;

  default:
    credentialDataRequest = {
      type: 'Raw',
      data: Array.from(new TextEncoder().encode(credentialData.raw_data || '')),
    };
    break;
}

  return credentialDataRequest;
};
