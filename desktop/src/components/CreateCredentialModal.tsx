import React, { useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useReauth } from '@/hooks/useReauth';
import type {
  Credential,
  CredentialData,
  CredentialType,
  SecurityLevel,
  CredentialDataRequest,
} from '@/types';
import { EyeIcon, EyeSlashIcon, KeyIcon } from '@heroicons/react/24/outline';
import ReauthModal from './ReauthModal';
import { credentialTypeLabel, securityLevelLabel } from './credentialDisplay';
import { useEscapeToClose } from '@/hooks/useEscapeToClose';

interface CreateCredentialModalProps {
  isOpen: boolean;
  onClose: () => void;
  /** 编辑模式：待编辑凭据 + 打开时面板已解密的 payload（null = 未取到）。
   *  缺省/ null = 创建模式。 */
  editCredential?: { credential: Credential; data: CredentialData | null } | null;
}

const parseOtpauthUri = (uri: string) => {
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

const CreateCredentialModal: React.FC<CreateCredentialModalProps> = ({
  isOpen,
  onClose,
  editCredential = null,
}) => {
  const {
    currentIdentity,
    createCredential,
    updateCredential,
    updateCredentialData,
    generatePassword,
    isLoading,
  } = usePersonaService();
  const { t } = useTranslation();
  const reauth = useReauth();
  const isEditMode = !!editCredential;
  // Esc 关闭：REAUTH 弹窗叠开时让位上层；提交中不逃逸（半提交态关闭观感割裂）
  useEscapeToClose(isOpen && !reauth.isOpen && !isLoading, onClose);
  // payload 保存命中 REAUTH_REQUIRED 后只自动重试一次（防循环）
  const retryRef = useRef(false);
  const [formData, setFormData] = useState({
    name: '',
    credential_type: 'Password' as CredentialType,
    security_level: 'High' as SecurityLevel,
    url: '',
    username: '',
    notes: '',
    tags: '',
  });

  const [credentialData, setCredentialData] = useState<any>({
    password: '',
    email: '',
    security_questions: [],
  });

  // 打开时初始化表单：编辑模式预填（payload 缺失字段留空），创建模式清残留
  useEffect(() => {
    if (!isOpen) return;
    retryRef.current = false;
    if (editCredential) {
      const c = editCredential.credential;
      const payload = editCredential.data;
      // GameToken 挂在 TwoFactor 类型上（创建约定），按 payload 变体还原表单类型
      let formType = c.credential_type as CredentialType;
      if (formType === 'TwoFactor' && payload?.credential_type === 'GameToken') {
        formType = 'GameToken';
      }
      setFormData({
        name: c.name,
        credential_type: formType,
        security_level: c.security_level as SecurityLevel,
        url: c.url ?? '',
        username: c.username ?? '',
        notes: c.notes ?? '',
        tags: c.tags.join(', '),
      });
      setCredentialData(payload?.data ? { ...payload.data } : {});
    } else {
      setFormData({
        name: '',
        credential_type: 'Password',
        security_level: 'High',
        url: '',
        username: '',
        notes: '',
        tags: '',
      });
      setCredentialData({
        password: '',
        email: '',
        security_questions: [],
      });
    }
  }, [isOpen, editCredential]);

  const [showPassword, setShowPassword] = useState(false);

  const credentialTypes: CredentialType[] = [
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

  const securityLevels: SecurityLevel[] = ['Critical', 'High', 'Medium', 'Low'];

  const handleGeneratePassword = async () => {
    const password = await generatePassword(16, true);
    if (password) {
      setCredentialData({ ...credentialData, password });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentIdentity || !formData.name.trim()) return;

    const tags = Array.from(
      new Set(
        formData.tags
          .split(',')
          .map((tag) => tag.trim())
          .filter(Boolean),
      ),
    );

    let credentialDataRequest: CredentialDataRequest;

    switch (formData.credential_type) {
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
          url: formData.url.trim() || undefined,
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

    if (isEditMode && editCredential) {
      // ---- 编辑：先存元数据（updateCredential 内部刷新列表 + toast）----
      const credentialId = editCredential.credential.id;
      const meta = await updateCredential({
        id: credentialId,
        name: formData.name,
        security_level: formData.security_level,
        // 空串交给后端 trim 清空（允许编辑时清掉 url/username/notes）
        url: formData.url,
        username: formData.username,
        notes: formData.notes,
        tags,
      });
      if (!meta) return; // 元数据失败：保持弹窗打开，错误已 toast

      // ---- payload 编辑：仅限表单有专属字段的类型 ----
      // 无专属字段（BankCard/ServerConfig/Certificate/GameAccount 等）提交
      // 会编码出空 Raw——盲目覆盖既有密文，所以这些类型只编辑元数据。
      const typesWithPayloadFields: CredentialType[] = [
        'Password',
        'TwoFactor',
        'GameToken',
        'SecureNote',
        'Identity',
        'SoftwareLicense',
        'CryptoWallet',
        'SshKey',
        'ApiKey',
      ];
      if (!typesWithPayloadFields.includes(formData.credential_type)) {
        onClose();
        return;
      }

      const doSavePayload = async (): Promise<boolean> => {
        const res = await updateCredentialData({
          credential_id: credentialId,
          credential_data: credentialDataRequest,
        });
        if (res.success) return true;
        if (res.error_code === 'REAUTH_REQUIRED') {
          // 弹重新认证；成功且未重试过则自动重放一次
          if (!retryRef.current && (await reauth.requestReauth())) {
            retryRef.current = true;
            return doSavePayload();
          }
          return false;
        }
        if (res.error_code === 'SERVICE_LOCKED') {
          toast.error(t('credForm.serviceLocked'));
        } else {
          toast.error(res.error || t('credForm.saveSecretFailed'));
        }
        return false;
      };
      // payload 保存失败保持弹窗打开（元数据已存，用户可重试密文部分）
      if (await doSavePayload()) onClose();
      return;
    }

    // ---- 创建 ----
    const result = await createCredential({
      identity_id: currentIdentity.id,
      name: formData.name,
      // GameToken data rides on the TwoFactor credential type (no dedicated
      // CredentialType variant — same convention as the CLI setup commands).
      credential_type: formData.credential_type === 'GameToken' ? 'TwoFactor' : formData.credential_type,
      security_level: formData.security_level,
      url: formData.url || undefined,
      username: formData.username || undefined,
      notes: formData.notes.trim() || undefined,
      tags: tags.length ? tags : undefined,
      credential_data: credentialDataRequest,
    });

    if (result) {
      onClose();
    }
  };

  const renderCredentialFields = () => {
    switch (formData.credential_type) {
      case 'Password':
        return (
          <div className="space-y-4">
            <div>
              <label className="label mb-2 block">{t('credForm.emailUsername')}</label>
              <input
                type="email"
                value={credentialData.email || ''}
                onChange={(e) => setCredentialData({ ...credentialData, email: e.target.value })}
                className="input"
                placeholder="user@example.com"
              />
            </div>
            <div>
              <label className="label mb-2 block">{t('credForm.passwordReq')}</label>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={credentialData.password || ''}
                    onChange={(e) => setCredentialData({ ...credentialData, password: e.target.value })}
                    className="input pr-10"
                    placeholder={t('credForm.passwordPlaceholder')}
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center"
                  >
                    {showPassword ? (
                      <EyeSlashIcon className="h-4 w-4 text-gray-400 dark:text-gray-500" />
                    ) : (
                      <EyeIcon className="h-4 w-4 text-gray-400 dark:text-gray-500" />
                    )}
                  </button>
                </div>
                <button
                  type="button"
                  onClick={handleGeneratePassword}
                  className="btn-secondary flex items-center"
                >
                  <KeyIcon className="w-4 h-4 mr-1" />
                  {t('credForm.generate')}
                </button>
              </div>
            </div>
          </div>
        );

      case 'CryptoWallet':
        return (
          <div className="space-y-4">
            <div>
              <label className="label mb-2 block">{t('credForm.walletTypeReq')}</label>
              <input
                type="text"
                value={credentialData.wallet_type || ''}
                onChange={(e) => setCredentialData({ ...credentialData, wallet_type: e.target.value })}
                className="input"
                placeholder={t('credForm.walletTypePlaceholder')}
                required
              />
            </div>
            <div>
              <label className="label mb-2 block">{t('credForm.addressReq')}</label>
              <input
                type="text"
                value={credentialData.address || ''}
                onChange={(e) => setCredentialData({ ...credentialData, address: e.target.value })}
                className="input"
                placeholder={t('credForm.addressPlaceholder')}
                required
              />
            </div>
            <div>
              <label className="label mb-2 block">{t('credForm.mnemonic')}</label>
              <textarea
                value={credentialData.mnemonic_phrase || ''}
                onChange={(e) => setCredentialData({ ...credentialData, mnemonic_phrase: e.target.value })}
                className="input h-20 resize-none"
                placeholder={t('credForm.mnemonicPlaceholder')}
              />
            </div>
            <div>
              <label className="label mb-2 block">{t('detail.labels.network')}</label>
              <select
                value={credentialData.network || 'mainnet'}
                onChange={(e) => setCredentialData({ ...credentialData, network: e.target.value })}
                className="input"
              >
                <option value="mainnet">{t('credForm.networkMainnet')}</option>
                <option value="testnet">{t('credForm.networkTestnet')}</option>
                <option value="regtest">{t('credForm.networkRegtest')}</option>
              </select>
            </div>
          </div>
        );

      case 'SshKey':
        return (
          <div className="space-y-4">
            <div>
              <label className="label mb-2 block">{t('detail.labels.keyType')}</label>
              <select
                value={credentialData.key_type || 'rsa'}
                onChange={(e) => setCredentialData({ ...credentialData, key_type: e.target.value })}
                className="input"
              >
                <option value="rsa">RSA</option>
                <option value="ed25519">Ed25519</option>
                <option value="ecdsa">ECDSA</option>
              </select>
            </div>
            <div>
              <label className="label mb-2 block">{t('credForm.publicKeyReq')}</label>
              <textarea
                value={credentialData.public_key || ''}
                onChange={(e) => setCredentialData({ ...credentialData, public_key: e.target.value })}
                className="input h-20 resize-none font-mono text-xs"
                placeholder="ssh-rsa AAAAB3NzaC1yc2E..."
                required
              />
            </div>
            <div>
              <label className="label mb-2 block">{t('credForm.privateKeyReq')}</label>
              <textarea
                value={credentialData.private_key || ''}
                onChange={(e) => setCredentialData({ ...credentialData, private_key: e.target.value })}
                className="input h-32 resize-none font-mono text-xs"
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                required
              />
            </div>
            <div>
              <label className="label mb-2 block">{t('detail.labels.passphrase')}</label>
              <input
                type="password"
                value={credentialData.passphrase || ''}
                onChange={(e) => setCredentialData({ ...credentialData, passphrase: e.target.value })}
                className="input"
                placeholder={t('credForm.passphrasePlaceholder')}
              />
            </div>
          </div>
        );

      case 'ApiKey':
        return (
          <div className="space-y-4">
            <div>
              <label className="label mb-2 block">{t('credForm.apiKeyReq')}</label>
              <input
                type="text"
                value={credentialData.api_key || ''}
                onChange={(e) => setCredentialData({ ...credentialData, api_key: e.target.value })}
                className="input font-mono"
                placeholder={t('credForm.apiKeyPlaceholder')}
                required
              />
            </div>
            <div>
              <label className="label mb-2 block">{t('detail.labels.apiSecret')}</label>
              <input
                type="password"
                value={credentialData.api_secret || ''}
                onChange={(e) => setCredentialData({ ...credentialData, api_secret: e.target.value })}
                className="input font-mono"
                placeholder={t('credForm.apiSecretPlaceholder')}
              />
            </div>
            <div>
              <label className="label mb-2 block">{t('detail.labels.permissions')}</label>
              <input
                type="text"
                value={(credentialData.permissions || []).join(', ')}
                onChange={(e) => setCredentialData({
                  ...credentialData,
                  permissions: e.target.value.split(',').map(p => p.trim()).filter(Boolean)
                })}
                className="input"
                placeholder={t('credForm.permissionsPlaceholder')}
              />
            </div>
          </div>
        );

      case 'TwoFactor':
        return (
          <div className="space-y-4">
            <div>
              <label className="label mb-2 block">{t('credForm.otpauthUri')}</label>
              <input
                type="text"
                value={credentialData.otpauth_uri || ''}
                onChange={(e) => {
                  const value = e.target.value;
                  const parsed = value.trim() ? parseOtpauthUri(value.trim()) : null;
                  if (parsed) {
                    setCredentialData({ ...credentialData, ...parsed, otpauth_uri: value });
                  } else {
                    setCredentialData({ ...credentialData, otpauth_uri: value });
                  }
                }}
                className="input font-mono text-xs"
                placeholder="otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&digits=6&period=30"
              />
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                {t('credForm.otpauthHint')}
              </p>
            </div>
            <div>
              <label className="label mb-2 block">{t('credForm.secretReq')}</label>
              <input
                type="text"
                value={credentialData.secret_key || ''}
                onChange={(e) => setCredentialData({ ...credentialData, secret_key: e.target.value })}
                className="input font-mono"
                placeholder="JBSWY3DPEHPK3PXP"
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label mb-2 block">{t('detail.labels.issuer')}</label>
                <input
                  type="text"
                  value={credentialData.issuer || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, issuer: e.target.value })}
                  className="input"
                  placeholder="GitHub"
                />
              </div>
              <div>
                <label className="label mb-2 block">{t('detail.labels.account')}</label>
                <input
                  type="text"
                  value={credentialData.account_name || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, account_name: e.target.value })}
                  className="input"
                  placeholder="user@example.com"
                />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <label className="label mb-2 block">{t('credForm.algorithm')}</label>
                <select
                  value={credentialData.algorithm || 'SHA1'}
                  onChange={(e) => setCredentialData({ ...credentialData, algorithm: e.target.value })}
                  className="input"
                >
                  <option value="SHA1">SHA1</option>
                  <option value="SHA256">SHA256</option>
                  <option value="SHA512">SHA512</option>
                </select>
              </div>
              <div>
                <label className="label mb-2 block">{t('credForm.digits')}</label>
                <select
                  value={String(credentialData.digits || 6)}
                  onChange={(e) => setCredentialData({ ...credentialData, digits: Number(e.target.value) })}
                  className="input"
                >
                  <option value="6">6</option>
                  <option value="8">8</option>
                </select>
              </div>
              <div>
                <label className="label mb-2 block">{t('credForm.period')}</label>
                <input
                  type="number"
                  min={10}
                  max={120}
                  value={credentialData.period || 30}
                  onChange={(e) => setCredentialData({ ...credentialData, period: Number(e.target.value) })}
                  className="input"
                />
              </div>
            </div>
          </div>
        );

      case 'GameToken':
        return (
          <div className="space-y-4">
            <div>
              <label className="label mb-2 block">{t('credForm.providerReq')}</label>
              <input
                type="text"
                value={credentialData.provider || ''}
                onChange={(e) => setCredentialData({ ...credentialData, provider: e.target.value })}
                className="input font-mono"
                placeholder="steam_guard, tencent_security, netease_dashen, mihoyo"
                required
              />
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                {t('credForm.providerHint')}
              </p>
            </div>
            <div>
              <label className="label mb-2 block">{t('credForm.sharedSecret')}</label>
              <input
                type="text"
                value={credentialData.secret_key || ''}
                onChange={(e) => setCredentialData({ ...credentialData, secret_key: e.target.value })}
                className="input font-mono"
                placeholder={t('credForm.sharedSecretPlaceholder')}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label mb-2 block">{t('detail.labels.issuer')}</label>
                <input
                  type="text"
                  value={credentialData.issuer || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, issuer: e.target.value })}
                  className="input"
                  placeholder="Steam, Tencent, NetEase…"
                />
              </div>
              <div>
                <label className="label mb-2 block">{t('credForm.accountReq')}</label>
                <input
                  type="text"
                  value={credentialData.account_name || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, account_name: e.target.value })}
                  className="input"
                  placeholder="qq_123456"
                  required
                />
              </div>
            </div>
          </div>
        );

      case 'SecureNote':
        return (
          <div>
            <label className="label mb-2 block">{t('credForm.noteReq')}</label>
            <textarea
              value={credentialData.note || ''}
              onChange={(e) => setCredentialData({ ...credentialData, note: e.target.value })}
              className="input h-40 resize-y font-mono text-sm"
              placeholder={t('credForm.notePlaceholder')}
              required
            />
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              {t('credForm.noteHint')}
            </p>
          </div>
        );

      case 'Identity':
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label mb-2 block" htmlFor="cred-first_name">{t('credForm.firstNameReq')}</label>
                <input
                  id="cred-first_name"
                  type="text"
                  value={credentialData.first_name || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, first_name: e.target.value })}
                  className="input"
                  required
                />
              </div>
              <div>
                <label className="label mb-2 block" htmlFor="cred-last_name">{t('credForm.lastNameReq')}</label>
                <input
                  id="cred-last_name"
                  type="text"
                  value={credentialData.last_name || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, last_name: e.target.value })}
                  className="input"
                  required
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label mb-2 block" htmlFor="cred-email">{t('detail.labels.email')}</label>
                <input
                  id="cred-email"
                  type="text"
                  value={credentialData.email || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, email: e.target.value })}
                  className="input"
                />
              </div>
              <div>
                <label className="label mb-2 block" htmlFor="cred-phone">{t('detail.labels.phone')}</label>
                <input
                  id="cred-phone"
                  type="text"
                  value={credentialData.phone || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, phone: e.target.value })}
                  className="input"
                />
              </div>
            </div>
            <div>
              <label className="label mb-2 block">{t('detail.labels.address')}</label>
              <textarea
                value={credentialData.address || ''}
                onChange={(e) => setCredentialData({ ...credentialData, address: e.target.value })}
                className="input h-20 resize-y"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label mb-2 block" htmlFor="cred-id_number">{t('detail.labels.idNumber')}</label>
                <input
                  id="cred-id_number"
                  type="text"
                  value={credentialData.id_number || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, id_number: e.target.value })}
                  className="input font-mono"
                />
              </div>
              <div>
                <label className="label mb-2 block" htmlFor="cred-passport_number">{t('detail.labels.passportNo')}</label>
                <input
                  id="cred-passport_number"
                  type="text"
                  value={credentialData.passport_number || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, passport_number: e.target.value })}
                  className="input font-mono"
                />
              </div>
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {t('credForm.identityDocHint')}
            </p>
          </div>
        );

      case 'SoftwareLicense':
        return (
          <div className="space-y-4">
            <div>
              <label className="label mb-2 block">{t('credForm.licenseKeyReq')}</label>
              <textarea
                value={credentialData.license_key || ''}
                onChange={(e) => setCredentialData({ ...credentialData, license_key: e.target.value })}
                className="input h-24 resize-y font-mono text-sm"
                placeholder="AAAA-BBBB-CCCC-DDDD"
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label mb-2 block" htmlFor="cred-version">{t('detail.labels.version')}</label>
                <input
                  id="cred-version"
                  type="text"
                  value={credentialData.version || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, version: e.target.value })}
                  className="input"
                  placeholder="2024.2"
                />
              </div>
              <div>
                <label className="label mb-2 block" htmlFor="cred-publisher">{t('detail.labels.publisher')}</label>
                <input
                  id="cred-publisher"
                  type="text"
                  value={credentialData.publisher || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, publisher: e.target.value })}
                  className="input"
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label mb-2 block" htmlFor="cred-seats">{t('detail.labels.seats')}</label>
                <input
                  id="cred-seats"
                  type="number"
                  min={1}
                  value={credentialData.seats || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, seats: e.target.value })}
                  className="input"
                />
              </div>
              <div>
                <label className="label mb-2 block" htmlFor="cred-valid_until">{t('detail.labels.validUntil')}</label>
                <input
                  id="cred-valid_until"
                  type="text"
                  value={credentialData.valid_until || ''}
                  onChange={(e) => setCredentialData({ ...credentialData, valid_until: e.target.value })}
                  className="input"
                  placeholder="2027-05-01"
                />
              </div>
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {t('credForm.licenseHint')}
            </p>
          </div>
        );

      default:
        return (
          <div>
            <label className="label mb-2 block">{t('credForm.data')}</label>
            <textarea
              value={credentialData.raw_data || ''}
              onChange={(e) => setCredentialData({ ...credentialData, raw_data: e.target.value })}
              className="input h-32 resize-none"
              placeholder={t('credForm.dataPlaceholder')}
            />
          </div>
        );
    }
  };

  if (!isOpen || !currentIdentity) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
      <div className="bg-white dark:bg-gray-900 rounded-lg p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <h2 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4" data-testid="credential-modal-title">
          {isEditMode ? t('credForm.editTitle') : t('credForm.addTitle')}
        </h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="label mb-2 block">{t('credForm.nameReq')}</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="input"
              placeholder={t('credForm.namePlaceholder')}
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label mb-2 block">{t('credForm.type')}</label>
              <select
                value={formData.credential_type}
                onChange={(e) => {
                  setFormData({ ...formData, credential_type: e.target.value as CredentialType });
                  setCredentialData({}); // Reset credential data when type changes
                }}
                className="input"
                disabled={isEditMode}
                data-testid="credential-type-select"
              >
                {credentialTypes.map((type) => (
                  <option key={type} value={type}>
                    {credentialTypeLabel(t, type)}
                  </option>
                ))}
              </select>
              {isEditMode && (
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  {t('credForm.typeLocked')}
                </p>
              )}
            </div>

            <div>
              <label className="label mb-2 block">{t('credForm.securityLevel')}</label>
              <select
                value={formData.security_level}
                onChange={(e) => setFormData({ ...formData, security_level: e.target.value as SecurityLevel })}
                className="input"
              >
                {securityLevels.map((level) => (
                  <option key={level} value={level}>
                    {securityLevelLabel(t, level)}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="label mb-2 block">{t('detail.labels.url')}</label>
            <input
              type="url"
              value={formData.url}
              onChange={(e) => setFormData({ ...formData, url: e.target.value })}
              className="input"
              placeholder="https://example.com"
            />
          </div>

          <div>
            <label className="label mb-2 block">{t('detail.labels.username')}</label>
            <input
              type="text"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              className="input"
              placeholder={t('credForm.usernamePlaceholder')}
            />
          </div>

          {renderCredentialFields()}

          <div>
            <label className="label mb-2 block">{t('detail.labels.notes')}</label>
            <textarea
              value={formData.notes}
              onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
              className="input h-20 resize-none"
              placeholder={t('credForm.notesPlaceholder')}
            />
          </div>

          <div>
            <label className="label mb-2 block">{t('detail.labels.tags')}</label>
            <input
              type="text"
              value={formData.tags}
              onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
              className="input"
              placeholder={t('credForm.tagsPlaceholder')}
            />
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{t('settings.commaSeparated')}</p>
          </div>

          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="btn-secondary flex-1"
            >
              {t('common.cancel')}
            </button>
            <button
              type="submit"
              disabled={isLoading || !formData.name.trim()}
              className="btn-primary flex-1"
            >
              {isLoading
                ? isEditMode
                  ? t('credForm.saving')
                  : t('credForm.creating')
                : isEditMode
                  ? t('common.save')
                  : t('credForm.createButton')}
            </button>
          </div>
        </form>

        {/* payload 保存命中 REAUTH_REQUIRED 时弹出，验证通过自动重试一次 */}
        <ReauthModal
          isOpen={reauth.isOpen}
          error={reauth.error}
          isVerifying={reauth.isVerifying}
          onSubmit={reauth.submit}
          onClose={reauth.cancel}
        />
      </div>
    </div>
  );
};

export default CreateCredentialModal;
