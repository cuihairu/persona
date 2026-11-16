import React, { useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useReauth } from '@/hooks/useReauth';
import type {
  Credential,
  CredentialData,
  CredentialType,
  CustomField,
  SecurityLevel,
} from '@/types';
import { personaAPI } from '@/utils/api';
import ReauthModal from './ReauthModal';
import { credentialTypeLabel, securityLevelLabel } from './credentialDisplay';
import { useEscapeToClose } from '@/hooks/useEscapeToClose';
import CredentialFieldsSection from './createCredential/CredentialFieldsSection';
import CustomFieldsEditor from './createCredential/CustomFieldsEditor';
import {
  buildCredentialDataRequest,
  CREDENTIAL_TYPE_OPTIONS,
  SECURITY_LEVEL_OPTIONS,
} from './createCredential/credentialFormModel';

interface CreateCredentialModalProps {
  isOpen: boolean;
  onClose: () => void;
  /** 编辑模式：待编辑凭据 + 打开时面板已解密的 payload（null = 未取到）。
   *  缺省/ null = 创建模式。 */
  editCredential?: { credential: Credential; data: CredentialData | null } | null;
}

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
    getCredentialData,
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

  // 钱包表单：助记词校验反馈、生成词数、高敏字段（第 25 词/私钥）显示切换
  const [mnemonicCheck, setMnemonicCheck] = useState<{
    valid: boolean;
    wordCount: number | null;
    error: string | null;
  } | null>(null);
  const [mnemonicWordCount, setMnemonicWordCount] = useState(24);
  const [showBip39Passphrase, setShowBip39Passphrase] = useState(false);
  const [showWalletPrivateKey, setShowWalletPrivateKey] = useState(false);

  // 助记词实时校验（BIP-39 词表+校验和，纯计算命令不触库不留存）；
  // 防抖 400ms 避免逐键打命令；切换类型或清空即清反馈
  useEffect(() => {
    if (formData.credential_type !== 'CryptoWallet') {
      setMnemonicCheck(null);
      return;
    }
    const phrase = (credentialData.mnemonic_phrase || '').trim();
    if (!phrase) {
      setMnemonicCheck(null);
      return;
    }
    const timer = setTimeout(() => {
      personaAPI
        .walletValidateMnemonic(phrase)
        .then((res) => {
          if (res.success && res.data) {
            setMnemonicCheck({
              valid: res.data.valid,
              wordCount: res.data.word_count,
              error: res.data.error,
            });
          } else {
            setMnemonicCheck(null);
          }
        })
        .catch(() => setMnemonicCheck(null));
    }, 400);
    return () => clearTimeout(timer);
  }, [credentialData.mnemonic_phrase, formData.credential_type]);

  const handleGenerateMnemonic = async () => {
    try {
      const res = await personaAPI.walletGenerateMnemonic(mnemonicWordCount);
      if (res.success && res.data) {
        const phrase = res.data;
        setCredentialData((prev: any) => ({ ...prev, mnemonic_phrase: phrase }));
      } else {
        toast.error(t('credForm.generateMnemonicFailed'));
      }
    } catch {
      toast.error(t('credForm.generateMnemonicFailed'));
    }
  };

  // 编辑模式下按 id 兜底补载密文 payload（调用方传 null 时不至于全空回显）；
  // 补载期间禁提交，避免拿空 payload 覆盖既有密文
  const [hydrating, setHydrating] = useState(false);

  // 自定义字段（gap #5 余项）：编辑表单里的增删改。整表读写——新行 id 传
  // 空串由后端生成；dirty 才落库，未动过的表不白写一轮密文
  const [customFields, setCustomFields] = useState<CustomField[]>([]);
  const [customFieldsError, setCustomFieldsError] = useState<string | null>(null);
  const [customFieldsDirty, setCustomFieldsDirty] = useState(false);
  const [revealedFieldIds, setRevealedFieldIds] = useState<Set<string>>(new Set());

  // 打开时初始化表单：编辑模式预填（payload 缺失字段留空），创建模式清残留
  useEffect(() => {
    if (!isOpen) return;
    retryRef.current = false;
    // 自定义字段整表读取（sealed blob 需解锁）。读取失败不提供编辑：
    // 保存是整表替换语义，读不到旧表就盲存会清掉既有字段
    let fieldsCancelled = false;
    setCustomFields([]);
    setCustomFieldsError(null);
    setCustomFieldsDirty(false);
    setRevealedFieldIds(new Set());
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
      void personaAPI.getCredentialCustomFields(c.id).then((res) => {
        if (fieldsCancelled) return;
        if (res.success && res.data) {
          setCustomFields(res.data);
        } else {
          setCustomFieldsError(res.error || t('detail.customFieldsLoadFailed'));
        }
      });
      if (!payload) {
        // 兜底补载：调用方没带 payload（详情页数据尚未加载/加载失败重试入口）
        let cancelled = false;
        setHydrating(true);
        void getCredentialData(c.id).then((fetched) => {
          if (cancelled) return;
          setHydrating(false);
          if (fetched?.data) {
            setCredentialData({ ...(fetched.data as Record<string, unknown>) });
          }
        });
        return () => {
          cancelled = true;
          fieldsCancelled = true;
        };
      }
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
    return () => {
      fieldsCancelled = true;
    };
  }, [isOpen, editCredential]);

  const [showPassword, setShowPassword] = useState(false);

  const handleGeneratePassword = async () => {
    const password = await generatePassword(16, true);
    if (password) {
      setCredentialData({ ...credentialData, password });
    }
  };

  // ---- 自定义字段（整表读写）----
  // 新行给 tmp- 前缀的本地 id（两条新行并存也要各自可寻址）；落库时映射回
  // 空串，由后端 set_credential_custom_fields 生成正式 uuid。已有行的 uuid
  // 不可能与 tmp- 撞
  const tmpFieldIdRef = useRef(0);
  const newFieldRow = (): CustomField => {
    tmpFieldIdRef.current += 1;
    return { id: `tmp-${tmpFieldIdRef.current}`, label: '', value: '', type: 'text', section: null };
  };

  const updateCustomField = (id: string, patch: Partial<CustomField>) => {
    setCustomFields((prev) => prev.map((f) => (f.id === id ? { ...f, ...patch } : f)));
    setCustomFieldsDirty(true);
  };

  const addCustomField = () => {
    setCustomFields((prev) => [...prev, newFieldRow()]);
    setCustomFieldsDirty(true);
  };

  const removeCustomField = (id: string) => {
    setCustomFields((prev) => prev.filter((f) => f.id !== id));
    setCustomFieldsDirty(true);
  };

  const toggleRevealField = (id: string) => {
    setRevealedFieldIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  /** 整表落库。全空行丢弃；成功后以服务端回传（含生成 id）重建本地表 */
  const persistCustomFields = async (credentialId: string): Promise<boolean> => {
    const rows = customFields
      .map((f) => ({
        ...f,
        label: f.label.trim(),
        section: (f.section ?? '').trim() || null,
      }))
      .filter((f) => f.label !== '' || f.value !== '')
      .map((f) => (f.id.startsWith('tmp-') ? { ...f, id: '' } : f));
    const res = await personaAPI.setCredentialCustomFields(credentialId, rows);
    if (res.success && res.data) {
      setCustomFields(res.data);
      setCustomFieldsDirty(false);
      return true;
    }
    toast.error(res.error || t('credForm.customFieldsSaveFailed'));
    return false;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentIdentity || !formData.name.trim()) return;
    // 密文 payload 还在补载：此刻提交会用空 payload 覆盖既有密文
    if (hydrating) return;

    const tags = Array.from(
      new Set(
        formData.tags
          .split(',')
          .map((tag) => tag.trim())
          .filter(Boolean),
      ),
    );

    const credentialDataRequest = buildCredentialDataRequest(
      formData.credential_type,
      credentialData,
      formData.url,
    );

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
        // 自定义字段挂在 metadata 上，与 payload 无关：无专属字段类型也照存
        if (customFieldsDirty && !(await persistCustomFields(credentialId))) return;
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
      if (await doSavePayload()) {
        // 字段排在 payload 之后：失败同样保持弹窗可重试（payload 幂等重封）
        if (customFieldsDirty && !(await persistCustomFields(credentialId))) return;
        onClose();
      }
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
      // 条目已创建：字段落库失败不回滚也不留弹窗（重提交会重复建条目），
      // toast 已报错，条目可从详情/编辑入口再补
      if (customFieldsDirty) await persistCustomFields(result.id);
      onClose();
    }
  };


  if (!isOpen || !currentIdentity) return null;

  return (
    <div
      className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50"
      onMouseDown={(e) => {
        // 点空白 = 取消（REAUTH 叠开/提交中不逃逸，与 Esc 同口径）；
        // 未保存输入直接丢弃——点外即取消是本批统一口径
        if (e.target === e.currentTarget && !reauth.isOpen && !isLoading) onClose();
      }}
    >
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
                {CREDENTIAL_TYPE_OPTIONS.map((type) => (
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
                {SECURITY_LEVEL_OPTIONS.map((level) => (
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

          <CredentialFieldsSection
            credentialType={formData.credential_type}
            credentialData={credentialData}
            setCredentialData={setCredentialData}
            showPassword={showPassword}
            setShowPassword={setShowPassword}
            handleGeneratePassword={handleGeneratePassword}
            mnemonicWordCount={mnemonicWordCount}
            setMnemonicWordCount={setMnemonicWordCount}
            mnemonicCheck={mnemonicCheck}
            handleGenerateMnemonic={handleGenerateMnemonic}
            showBip39Passphrase={showBip39Passphrase}
            setShowBip39Passphrase={setShowBip39Passphrase}
            showWalletPrivateKey={showWalletPrivateKey}
            setShowWalletPrivateKey={setShowWalletPrivateKey}
          />

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

{/* 自定义字段编辑（gap #5 余项）：整表替换语义。读取失败不渲染编辑器
              ——读不到旧表还盲存会把既有字段清掉 */}
          <CustomFieldsEditor
            customFieldsError={customFieldsError}
            customFields={customFields}
            revealedFieldIds={revealedFieldIds}
            addCustomField={addCustomField}
            updateCustomField={updateCustomField}
            removeCustomField={removeCustomField}
            toggleRevealField={toggleRevealField}
          />

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
              disabled={isLoading || hydrating || !formData.name.trim()}
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
