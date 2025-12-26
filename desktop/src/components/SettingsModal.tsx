import React, { useMemo, useState } from 'react';
import { usePersonaService } from '@/hooks/usePersonaService';
import type { Identity, IdentityType } from '@/types';
import { PencilSquareIcon, TrashIcon } from '@heroicons/react/24/outline';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const identityTypes: IdentityType[] = ['Personal', 'Work', 'Social', 'Financial', 'Gaming'];

const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose }) => {
  const { identities, currentIdentity, updateIdentity, deleteIdentity, isLoading } =
    usePersonaService();

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

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        <div className="p-6 border-b border-gray-100 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Settings</h2>
            <p className="text-sm text-gray-500">Manage identities</p>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-gray-100 rounded-lg" title="Close">
            ✕
          </button>
        </div>

        <div className="p-6">
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
        </div>
      </div>
    </div>
  );
};

export default SettingsModal;

