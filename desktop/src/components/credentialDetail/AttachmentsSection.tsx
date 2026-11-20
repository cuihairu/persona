import React from 'react';
import { useTranslation } from 'react-i18next';
import {
  ArrowDownTrayIcon,
  PaperClipIcon,
  PlusIcon,
  TrashIcon,
} from '@heroicons/react/24/outline';
import type { AttachmentEntry } from '@/types';

/** 附件区（原 JSX 块平移）：列表、落盘与删除入口由父级状态驱动。 */
const AttachmentsSection: React.FC<{
  attachments: AttachmentEntry[];
  isAttachmentBusy: boolean;
  handleAttachFile: () => Promise<void>;
  handleSaveAttachment: (attachment: AttachmentEntry) => Promise<void>;
  handleDeleteAttachment: (attachment: AttachmentEntry) => Promise<void>;
}> = ({
  attachments,
  isAttachmentBusy,
  handleAttachFile,
  handleSaveAttachment,
  handleDeleteAttachment,
}) => {
  const { t } = useTranslation();

// Attachments（1Password 对齐）：附件经凭据 item key 加密封存
  return (
    <div className="border-t pt-3">
      <div className="flex items-center justify-between">
        <span className="flex items-center gap-1 text-sm text-gray-600 dark:text-gray-300">
          <PaperClipIcon className="w-4 h-4" />
          {t('detail.attachments')}
        </span>
        <button
          type="button"
          onClick={handleAttachFile}
          disabled={isAttachmentBusy}
          data-testid="attachment-add"
          className="whitespace-nowrap flex items-center gap-1 text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-50"
        >
          <PlusIcon className="w-3.5 h-3.5" />
          {t('detail.addFile')}
        </button>
      </div>

      <div className="mt-2" data-testid="attachment-list">
        {attachments.length === 0 ? (
          <p className="text-xs text-gray-400 dark:text-gray-500">
            {t('detail.noAttachments')}
          </p>
        ) : (
          <ul className="space-y-1.5">
            {attachments.map((attachment) => (
              <li
                key={attachment.id}
                className="flex items-center justify-between gap-2 text-xs bg-gray-50 dark:bg-gray-800 rounded p-2"
                data-testid="attachment-entry"
              >
                <div className="min-w-0">
                  <p
                    className="truncate font-medium text-gray-700 dark:text-gray-200"
                    data-testid="attachment-filename"
                  >
                    {attachment.filename}
                  </p>
                  <p className="text-gray-400 dark:text-gray-500">
                    {formatFileSize(attachment.size)}
                    {attachment.is_encrypted && t('detail.encryptedBadge')}
                  </p>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <button
                    type="button"
                    onClick={() => handleSaveAttachment(attachment)}
                    disabled={isAttachmentBusy}
                    title={t('detail.saveToDisk', { name: attachment.filename })}
                    data-testid={`attachment-save-${attachment.id}`}
                    className="whitespace-nowrap p-1 rounded text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50"
                  >
                    <ArrowDownTrayIcon className="w-4 h-4" />
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDeleteAttachment(attachment)}
                    disabled={isAttachmentBusy}
                    title={t('detail.deleteFile', { name: attachment.filename })}
                    data-testid={`attachment-delete-${attachment.id}`}
                    className="p-1 rounded text-gray-500 dark:text-gray-400 hover:bg-red-50 dark:hover:bg-red-900/30 hover:text-red-600 dark:hover:text-red-400 disabled:opacity-50"
                  >
                    <TrashIcon className="w-4 h-4" />
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

/** 人类可读的附件大小（B → KB → MB） */
function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default AttachmentsSection;
