import React, { useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { usePersonaService } from '@/hooks/usePersonaService';
import { personaAPI } from '@/utils/api';
import { useAppStore } from '@/stores/appStore';
import type { FeatureFlags, Identity, IdentityType } from '@/types';
import { PencilSquareIcon, TrashIcon } from '@heroicons/react/24/outline';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type SettingsTab = 'general' | 'identities';

const identityTypes: IdentityType[] = ['Personal', 'Work', 'Social', 'Financial', 'Gaming'];

/** General 面板的高级功能开关行（1Password 式默认关、opt-in 开） */
const FEATURE_ROWS: {
  key: keyof FeatureFlags;
  label: string;
  hint: string;
  /** 开关生效需要重新解锁等额外说明 */
  note?: string;
}[] = [
  { key: 'ssh_agent', label: 'SSH Agent', hint: 'Let terminals and browsers sign with keys stored in Persona' },
  { key: 'wallet', label: 'Wallets', hint: 'Manage on-chain wallets and sign transactions' },
  {
    key: 'passkeys',
    label: 'Passkeys',
    hint: 'Manage passkeys and run the browser approval server',
    note: 'Takes effect the next time you unlock',
  },
];

const GeneralPane: React.FC = () => {
  const featureFlags = useAppStore((s) => s.featureFlags);
  const setFeatureFlags = useAppStore((s) => s.setFeatureFlags);

  // optimistic 写入 → 服务端真相回填；失败回滚并 toast
  const toggle = async (key: keyof FeatureFlags) => {
    const previous = featureFlags;
    const next = { ...previous, [key]: !previous[key] };
    setFeatureFlags(next);

    try {
      const resp = await personaAPI.setFeatureFlags(next);
      if (resp.success && resp.data) {
        setFeatureFlags(resp.data.features);
      } else {
        setFeatureFlags(previous);
        toast.error(resp.error || 'Failed to save settings');
      }
    } catch (err) {
      setFeatureFlags(previous);
      toast.error(err instanceof Error ? err.message : 'Failed to save settings');
    }
  };

  return (
    <div>
      <h3 className="text-sm font-medium text-gray-900 mb-1">Advanced features</h3>
      <p className="text-xs text-gray-500 mb-3">
        Advanced features are off by default. Turn on only what you need.
      </p>
      <div className="border border-gray-200 rounded-lg divide-y divide-gray-100">
        {FEATURE_ROWS.map((row) => (
          <div key={row.key} className="flex items-center justify-between gap-4 px-4 py-3">
            <div className="min-w-0">
              <p className="text-sm font-medium text-gray-900">{row.label}</p>
              <p className="text-xs text-gray-500">{row.hint}</p>
              {row.note && <p className="text-xs text-gray-400">{row.note}</p>}
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={featureFlags[row.key]}
              aria-label={row.label}
              data-testid={`feature-toggle-${row.key}`}
              onClick={() => toggle(row.key)}
              className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors ${
                featureFlags[row.key] ? 'bg-primary-600' : 'bg-gray-200'
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                  featureFlags[row.key] ? 'translate-x-6' : 'translate-x-1'
                }`}
              />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};

const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose }) => {
  const { identities, currentIdentity, updateIdentity, deleteIdentity, isLoading } =
    usePersonaService();

  const [tab, setTab] = useState<SettingsTab>('general');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState<Partial<Identity>>({});
  const [draftTags, setDraftTags] = useState<string>('');

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
      `Delete identity "${identity.name}"? This will remove the identity and its data.`,
    );
    if (!confirmed) return;
    await deleteIdentity(identity.id);
    if (editingId === identity.id) cancelEdit();
  };

  if (!isOpen) return null;

  const tabs: { id: SettingsTab; label: string }[] = [
    { id: 'general', label: 'General' },
    { id: 'identities', label: 'Identities' },
  ];

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        <div className="p-6 pb-0 border-b border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Settings</h2>
              <p className="text-sm text-gray-500">
                {tab === 'general' ? 'Preferences and feature flags' : 'Manage identities'}
              </p>
            </div>
            <button onClick={onClose} className="p-2 hover:bg-gray-100 rounded-lg" title="Close">
              ✕
            </button>
          </div>

          <div className="flex gap-1 mt-4" role="tablist">
            {tabs.map((t) => (
              <button
                key={t.id}
                role="tab"
                aria-selected={tab === t.id}
                onClick={() => setTab(t.id)}
                className={`px-3 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                  tab === t.id
                    ? 'text-primary-700 border-b-2 border-primary-600'
                    : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        <div className="p-6">
          {tab === 'general' ? (
            <GeneralPane />
          ) : (
            <div className="space-y-3">
              {identities.length === 0 ? (
                <div className="text-sm text-gray-500">No identities yet.</div>
              ) : (
                identities.map((identity) => {
                  const isEditing = editingId === identity.id;
                  const isCurrent = currentIdentity?.id === identity.id;

                  return (
                    <div
                      key={identity.id}
                      className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0 flex-1">
                          {isEditing ? (
                            <div className="space-y-3">
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="label mb-1 block">Name</label>
                                  <input
                                    className="input"
                                    value={(draft.name as string) || ''}
                                    onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                                  />
                                </div>
                                <div>
                                  <label className="label mb-1 block">Type</label>
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
                                  <label className="label mb-1 block">Email</label>
                                  <input
                                    className="input"
                                    value={(draft.email as string) || ''}
                                    onChange={(e) => setDraft({ ...draft, email: e.target.value })}
                                  />
                                </div>
                                <div>
                                  <label className="label mb-1 block">Phone</label>
                                  <input
                                    className="input"
                                    value={(draft.phone as string) || ''}
                                    onChange={(e) => setDraft({ ...draft, phone: e.target.value })}
                                  />
                                </div>
                              </div>

                              <div>
                                <label className="label mb-1 block">Description</label>
                                <textarea
                                  className="input h-20 resize-none"
                                  value={(draft.description as string) || ''}
                                  onChange={(e) =>
                                    setDraft({ ...draft, description: e.target.value })
                                  }
                                />
                              </div>

                              <div>
                                <label className="label mb-1 block">Tags</label>
                                <input
                                  className="input"
                                  value={draftTags}
                                  onChange={(e) => setDraftTags(e.target.value)}
                                  placeholder="Comma-separated"
                                />
                              </div>

                              <div className="flex gap-2 pt-2">
                                <button
                                  type="button"
                                  onClick={cancelEdit}
                                  className="btn-secondary"
                                >
                                  Cancel
                                </button>
                                <button
                                  type="button"
                                  onClick={saveEdit}
                                  disabled={isLoading || !(draft.name as string)?.trim()}
                                  className="btn-primary"
                                >
                                  {isLoading ? 'Saving…' : 'Save'}
                                </button>
                              </div>
                            </div>
                          ) : (
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <p className="text-sm font-semibold text-gray-900 truncate">
                                  {identity.name}
                                </p>
                                {isCurrent && (
                                  <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-primary-100 text-primary-700">
                                    Current
                                  </span>
                                )}
                              </div>
                              <p className="text-xs text-gray-500">
                                {identity.identity_type}
                                {identity.email ? ` • ${identity.email}` : ''}
                                {identity.phone ? ` • ${identity.phone}` : ''}
                              </p>
                              {identity.description && (
                                <p className="text-xs text-gray-600">{identity.description}</p>
                              )}
                              {identity.tags.length > 0 && (
                                <div className="flex flex-wrap gap-1 pt-1">
                                  {identity.tags.map((tag) => (
                                    <span
                                      key={tag}
                                      className="px-2 py-0.5 text-xs font-medium bg-gray-100 text-gray-700 rounded-full"
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
                              className="p-2 hover:bg-gray-100 rounded-lg"
                              onClick={() => startEdit(identity)}
                              title="Edit"
                            >
                              <PencilSquareIcon className="w-5 h-5 text-gray-500" />
                            </button>
                            <button
                              className="p-2 hover:bg-red-50 rounded-lg"
                              onClick={() => handleDelete(identity)}
                              title="Delete"
                            >
                              <TrashIcon className="w-5 h-5 text-red-600" />
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
