import React from 'react';
import { useTranslation } from 'react-i18next';
import { useAppStore } from '@/stores/appStore';
import type { TravelStatus } from '@/types';

/** 旅行模式状态行（SecurityPane 底部）：inactive 显 enter 入口、active 显
 *  exit 入口；inconsistent（旗标在但 sidecar 没了）红警告诚实告知数据已丢 */
const TravelModeSection: React.FC<{
  status: TravelStatus | null;
  busy: boolean;
  onEnter: () => void;
  onExit: () => void;
}> = ({ status, busy, onEnter, onExit }) => {
  const { t } = useTranslation();
  const identities = useAppStore((s) => s.identities);
  const markedCount = identities.filter((i) => i.travel_marked).length;

  return (
    <div className="flex items-start justify-between gap-4" data-testid="travel-section">
      <div className="min-w-0">
        <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
          {t('settings.travel.title')}
        </p>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          {status?.active
            ? t('settings.travel.activeHint', {
                time: status.entered_at ?? '',
              })
            : t('settings.travel.inactiveHint', { count: markedCount })}
        </p>
        {status?.inconsistent && (
          <p
            className="mt-2 text-xs text-red-600 dark:text-red-400"
            data-testid="travel-inconsistent-warning"
          >
            {t('settings.travel.inconsistentWarning')}
          </p>
        )}
      </div>
      {status?.active ? (
        <button
          type="button"
          data-testid="travel-exit-button"
          onClick={onExit}
          disabled={busy}
          className="btn-secondary flex-shrink-0"
        >
          {t('settings.travel.exitButton')}
        </button>
      ) : (
        <button
          type="button"
          data-testid="travel-enter-button"
          onClick={onEnter}
          disabled={busy}
          className="btn-secondary flex-shrink-0"
        >
          {t('settings.travel.enterButton')}
        </button>
      )}
    </div>
  );
};


export default TravelModeSection;
