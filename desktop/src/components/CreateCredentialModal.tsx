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
  /** Edit mode: the credential to edit + the payload the pane already decrypted
   *  when it opened (null = not fetched). Absent / null = create mode. */
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
  // Esc closes: yields to a stacked REAUTH dialog on top; no escape mid-submit (closing in a half-submitted state looks jarring)
  useEscapeToClose(isOpen && !reauth.isOpen && !isLoading, onClose);
  // After a payload save hits REAUTH_REQUIRED, auto-retry only once (loop prevention)
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

  // Wallet form: mnemonic validation feedback, generated word count, and sensitive-field (25th word / private key) visibility toggles
  const [mnemonicCheck, setMnemonicCheck] = useState<{
    valid: boolean;
    wordCount: number | null;
    error: string | null;
  } | null>(null);
  const [mnemonicWordCount, setMnemonicWordCount] = useState(24);
  const [showBip39Passphrase, setShowBip39Passphrase] = useState(false);
  const [showWalletPrivateKey, setShowWalletPrivateKey] = useState(false);

  // Live mnemonic validation (BIP-39 word list + checksum; a pure-compute
  // command that never touches the vault or persists anything);
  // debounced 400ms to avoid running the command per keystroke; switching
  // type or clearing the field resets the feedback
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

  // In edit mode, fall back to loading the encrypted payload by id (keeps the
  // echo from being entirely empty when the caller passes null);
  // submitting is disabled while the load is in flight, so an empty payload
  // cannot overwrite the existing ciphertext
  const [hydrating, setHydrating] = useState(false);

  // Custom fields (remaining item from gap #5): add/remove/edit rows in the edit
  // form. Whole-table read/write — a new row passes an empty id and the backend
  // generates it; only dirty tables get persisted, so an untouched table does not
  // burn a round of ciphertext for nothing
  const [customFields, setCustomFields] = useState<CustomField[]>([]);
  const [customFieldsError, setCustomFieldsError] = useState<string | null>(null);
  const [customFieldsDirty, setCustomFieldsDirty] = useState(false);
  const [revealedFieldIds, setRevealedFieldIds] = useState<Set<string>>(new Set());

  // Initialize the form on open: prefill in edit mode (fields missing from the payload stay empty), clear leftovers in create mode
  useEffect(() => {
    if (!isOpen) return;
    retryRef.current = false;
    // Read the custom fields as a whole table (a sealed blob requires unlock). A
    // failed read disables editing: saving is whole-table replacement, and blind
    // writing without the old table would wipe the existing fields
    let fieldsCancelled = false;
    setCustomFields([]);
    setCustomFieldsError(null);
    setCustomFieldsDirty(false);
    setRevealedFieldIds(new Set());
    if (editCredential) {
      const c = editCredential.credential;
      const payload = editCredential.data;
      // GameToken rides on the TwoFactor type (a creation convention); restore the form type from the payload variant
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
        // Fallback load: the caller arrived without a payload (detail-page data not yet loaded / retry entry after a failed load)
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

  // ---- Custom fields (whole-table read/write) ----
  // New rows get a tmp- prefixed local id (two new rows coexisting must each stay
  // addressable); on persist it maps back to an empty string, and the backend
  // set_credential_custom_fields generates the real uuid. A uuid of an existing
  // row can never collide with tmp-
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

  /** Persist the whole table. Fully empty rows are dropped; on success the local table is rebuilt from the server response (including generated ids) */
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
    // The encrypted payload is still loading: submitting right now would overwrite the existing ciphertext with an empty payload
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
      // ---- Edit: persist metadata first (updateCredential refreshes the list and toasts internally) ----
      const credentialId = editCredential.credential.id;
      const meta = await updateCredential({
        id: credentialId,
        name: formData.name,
        security_level: formData.security_level,
        // An empty string lets the backend trim clear the field (editing may clear url/username/notes)
        url: formData.url,
        username: formData.username,
        notes: formData.notes,
        tags,
      });
      if (!meta) return; // Metadata failed: keep the dialog open, the error is already toasted

      // ---- Payload editing: only for types with dedicated form fields ----
      // Types without dedicated fields (BankCard/ServerConfig/Certificate/GameAccount
      // etc.) would encode an empty Raw on submit — blindly overwriting the existing
      // ciphertext — so those types only edit metadata.
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
        // Custom fields hang off metadata, unrelated to the payload: types without dedicated fields still save them
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
          // Surface re-authentication; on success and if not retried yet, replay once automatically
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
      // A failed payload save keeps the dialog open (metadata is saved; the user can retry the ciphertext part)
      if (await doSavePayload()) {
        // Fields come after the payload: on failure the dialog likewise stays open for retry (the payload re-seals idempotently)
        if (customFieldsDirty && !(await persistCustomFields(credentialId))) return;
        onClose();
      }
      return;
    }

    // ---- Create ----
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
      // The entry is created: a failed field persist neither rolls back nor keeps the
      // dialog open (resubmitting would duplicate the entry); the toast already
      // reports the error, and the fields can be filled in later via detail/edit
      if (customFieldsDirty) await persistCustomFields(result.id);
      onClose();
    }
  };


  if (!isOpen || !currentIdentity) return null;

  return (
    <div
      className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50"
      onMouseDown={(e) => {
        // Clicking the backdrop = cancel (no escape while a REAUTH dialog is stacked
        // or a submit is in flight, same rule as Esc);
        // unsaved input is discarded outright — click-outside-cancels is the unified
        // rule across this batch
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

{/* Custom field editing (remaining item from gap #5): whole-table replacement
              semantics. A failed read renders no editor — blind-saving without the
              old table would wipe the existing fields */}
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

        {/* Shown when a payload save hits REAUTH_REQUIRED; auto-retries once after verification passes */}
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
