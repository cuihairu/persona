import React, { useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { usePersonaService } from '@/hooks/usePersonaService';
import { personaAPI } from '@/utils/api';
import type { Identity, IdentityType } from '@/types';
import { PencilSquareIcon, TrashIcon } from '@heroicons/react/24/outline';
import { useEscapeToClose } from '@/hooks/useEscapeToClose';
import GeneralPane from './settings/GeneralPane';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type SettingsTab = 'general' | 'identities';

const identityTypes: IdentityType[] = ['Personal', 'Work', 'Social', 'Financial', 'Gaming'];
const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose }) => {
  const { t } = useTranslation();
  const { identities, currentIdentity, updateIdentity, deleteIdentity, isLoading, loadIdentities } =
    usePersonaService();

  const [tab, setTab] = useState<SettingsTab>('general');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState<Partial<Identity>>({});
  const [draftTags, setDraftTags] = useState<string>('');
  // travel 标记开关是即时生效（非草稿字段）：请求中锁行防双击
  const [markBusyId, setMarkBusyId] = useState<string | null>(null);
  // 改密弹窗开关提升到本层：SettingsModal 的 Esc 在其叠开时让位上层
  const [changingPassword, setChangingPassword] = useState(false);
  useEscapeToClose(isOpen && !changingPassword, onClose);

  const toggleTravelMark = async (identity: Identity) => {
    setMarkBusyId(identity.id);
    try {
      const resp = await personaAPI.setTravelMarked(identity.id, !identity.travel_marked);
      if (resp.success) {
        await loadIdentities();
      } else {
        toast.error(resp.error || t('settings.travel.markFailed'));
      }
    } catch {
      toast.error(t('settings.travel.markFailed'));
    } finally {
      setMarkBusyId(null);
    }
  };

  const editingIdentity = useMemo(
    () => identities.find((id) => id.id === editingId) ?? null,
    [editingId, identities],
  );

  const startEdit = (identity: Identity) => {
    setEditingId(identity.id);
    setDraft({ ...identity });
    setDraftTags(identity.tags.join(', '));
  };

  const cancelEdit = () => {
    setEditingId(null);
    setDraft({});
    setDraftTags('');
  };

  const saveEdit = async () => {
    if (!editingIdentity) return;
    const name = (draft.name || '').trim();
    if (!name) return;

    const tags = Array.from(
      new Set(
        draftTags
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean),
      ),
    );

    const updated: Identity = {
      ...editingIdentity,
      ...draft,
      name,
      identity_type: (draft.identity_type as string) || editingIdentity.identity_type,
      tags,
    };

    const res = await updateIdentity(updated);
    if (res) cancelEdit();
  };

  const handleDelete = async (identity: Identity) => {
    const confirmed = window.confirm(
      t('settings.deleteIdentityConfirm', { name: identity.name }),
    );
    if (!confirmed) return;
    await deleteIdentity(identity.id);
    if (editingId === identity.id) cancelEdit();
  };

  if (!isOpen) return null;

  const tabs: { id: SettingsTab; label: string }[] = [
    { id: 'general', label: t('settings.tabGeneral') },
    { id: 'identities', label: t('settings.tabIdentities') },
  ];

  return (
    <div
      className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50"
      onMouseDown={(e) => {
        // 点空白 = 关闭；改密子弹框打开时不逃逸（与 Esc 同口径）
        if (e.target === e.currentTarget && !changingPassword) onClose();
      }}
    >
      <div className="bg-white dark:bg-gray-900 rounded-lg w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        <div className="p-6 pb-0 border-b border-gray-100 dark:border-gray-800">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">{t('settings.title')}</h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {tab === 'general' ? t('settings.subtitleGeneral') : t('settings.subtitleIdentities')}
              </p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
              title={t('settings.close')}
            >
              ✕
            </button>
          </div>

          <div className="flex gap-1 mt-4" role="tablist">
            {tabs.map((tabItem) => (
              <button
                key={tabItem.id}
                role="tab"
                aria-selected={tab === tabItem.id}
                onClick={() => setTab(tabItem.id)}
                className={`px-3 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                  tab === tabItem.id
                    ? 'text-primary-700 dark:text-primary-300 border-b-2 border-primary-600'
                    : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                {tabItem.label}
              </button>
            ))}
          </div>
        </div>

        <div className="p-6">
          {tab === 'general' ? (
            <GeneralPane
              changingPassword={changingPassword}
              setChangingPassword={setChangingPassword}
            />
          ) : (
            <div className="space-y-3">
              {identities.length === 0 ? (
                <div className="text-sm text-gray-500 dark:text-gray-400">{t('settings.noIdentitiesYet')}</div>
              ) : (
                identities.map((identity) => {
                  const isEditing = editingId === identity.id;
                  const isCurrent = currentIdentity?.id === identity.id;

                  return (
                    <div
                      key={identity.id}
                      className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-800/50"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0 flex-1">
                          {isEditing ? (
                            <div className="space-y-3">
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="label mb-1 block">{t('settings.name')}</label>
                                  <input
                                    className="input"
                                    value={(draft.name as string) || ''}
                                    onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                                  />
                                </div>
                                <div>
                                  <label className="label mb-1 block">{t('settings.type')}</label>
                                  <select
                                    className="input"
                                    value={(draft.identity_type as string) || identity.identity_type}
                                    onChange={(e) =>
                                      setDraft({ ...draft, identity_type: e.target.value })
                                    }
                                  >
                                    {identityTypes.map((t) => (
                                      <option key={t} value={t}>
                                        {t}
                                      </option>
                                    ))}
                                  </select>
                                </div>
                              </div>

                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="label mb-1 block">{t('settings.email')}</label>
                                  <input
                                    className="input"
                                    value={(draft.email as string) || ''}
                                    onChange={(e) => setDraft({ ...draft, email: e.target.value })}
                                  />
                                </div>
                                <div>
                                  <label className="label mb-1 block">{t('settings.phone')}</label>
                                  <input
                                    className="input"
                                    value={(draft.phone as string) || ''}
                                    onChange={(e) => setDraft({ ...draft, phone: e.target.value })}
                                  />
                                </div>
                              </div>

                              <div>
                                <label className="label mb-1 block">{t('settings.description')}</label>
                                <textarea
                                  className="input h-20 resize-none"
                                  value={(draft.description as string) || ''}
                                  onChange={(e) =>
                                    setDraft({ ...draft, description: e.target.value })
                                  }
                                />
                              </div>

                              <div>
                                <label className="label mb-1 block">{t('settings.tags')}</label>
                                <input
                                  className="input"
                                  value={draftTags}
                                  onChange={(e) => setDraftTags(e.target.value)}
                                  placeholder={t('settings.commaSeparated')}
                                />
                              </div>

                              {/* 旅行模式标记：即时生效（enter 时随之移出本设备）。
                                  enter 之后该身份已从列表移除，故"激活中"的
                                  disabled 天然不可达，无需全局 travel 状态。 */}
                              <div className="flex items-center justify-between gap-3">
                                <div className="min-w-0">
                                  <label className="label mb-1 block">
                                    {t('settings.travel.markLabel')}
                                  </label>
                                  <p className="text-xs text-gray-500 dark:text-gray-400">
                                    {t('settings.travel.markHint')}
                                  </p>
                                </div>
                                <button
                                  type="button"
                                  role="switch"
                                  aria-checked={identity.travel_marked}
                                  aria-label={t('settings.travel.markLabel')}
                                  data-testid={`travel-mark-toggle-${identity.id}`}
                                  disabled={markBusyId === identity.id}
                                  onClick={() => void toggleTravelMark(identity)}
                                  className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                                    identity.travel_marked
                                      ? 'bg-primary-600'
                                      : 'bg-gray-200 dark:bg-gray-700'
                                  }`}
                                >
                                  <span
                                    className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                                      identity.travel_marked ? 'translate-x-6' : 'translate-x-1'
                                    }`}
                                  />
                                </button>
                              </div>

                              <div className="flex gap-2 pt-2">
                                <button
                                  type="button"
                                  onClick={cancelEdit}
                                  className="btn-secondary"
                                >
                                  {t('common.cancel')}
                                </button>
                                <button
                                  type="button"
                                  onClick={saveEdit}
                                  disabled={isLoading || !(draft.name as string)?.trim()}
                                  className="btn-primary"
                                >
                                  {isLoading ? t('settings.saving') : t('common.save')}
                                </button>
                              </div>
                            </div>
                          ) : (
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <p className="text-sm font-semibold text-gray-900 dark:text-gray-100 truncate">
                                  {identity.name}
                                </p>
                                {isCurrent && (
                                  <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-primary-100 text-primary-700 dark:bg-primary-500/20 dark:text-primary-300">
                                    {t('settings.current')}
                                  </span>
                                )}
                              </div>
                              <p className="text-xs text-gray-500 dark:text-gray-400">
                                {identity.identity_type}
                                {identity.email ? ` • ${identity.email}` : ''}
                                {identity.phone ? ` • ${identity.phone}` : ''}
                              </p>
                              {identity.description && (
                                <p className="text-xs text-gray-600 dark:text-gray-300">
                                  {identity.description}
                                </p>
                              )}
                              {identity.tags.length > 0 && (
                                <div className="flex flex-wrap gap-1 pt-1">
                                  {identity.tags.map((tag) => (
                                    <span
                                      key={tag}
                                      className="px-2 py-0.5 text-xs font-medium bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 rounded-full"
                                    >
                                      {tag}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          )}
                        </div>

                        {!isEditing && (
                          <div className="flex items-center gap-1">
                            <button
                              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
                              onClick={() => startEdit(identity)}
                              title={t('common.edit')}
                            >
                              <PencilSquareIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
                            </button>
                            <button
                              className="p-2 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg"
                              onClick={() => handleDelete(identity)}
                              title={t('common.delete')}
                            >
                              <TrashIcon className="w-5 h-5 text-red-600 dark:text-red-400" />
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SettingsModal;
