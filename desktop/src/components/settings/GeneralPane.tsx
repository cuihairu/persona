import React, { useRef, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import i18n from '@/i18n';
import { personaAPI } from '@/utils/api';
import { trayLocaleLabels } from '@/utils/trayLocale';
import { useAppStore } from '@/stores/appStore';
import type { FeatureFlags, ThemePreference } from '@/types';
import ConnectAutomationSection from '../ConnectAutomationSection';
import AccountSection from '../AccountSection';
import QuickAccessSection from '../QuickAccessSection';
import GeneratorHotkeySection from '../GeneratorHotkeySection';
import UpdateCheckSection from '../UpdateCheckSection';
import BackupSection from '../BackupSection';
import DataLossWarning from '../DataLossWarning';
import SyncGroupSection from '../SyncGroupSection';
import SshIntegrationSection from '../SshIntegrationSection';
import SyncServerPane from './SyncServerPane';
import SyncMethodsSection from './SyncMethodsSection';
import SyncTransportSection from './SyncTransportSection';
import SyncDevicesSection from './SyncDevicesSection';
import SecurityPane from './SecurityPane';


// label holds an i18n key (module-level constants can't call hooks; t() is applied at render time)
const THEME_OPTIONS: { value: ThemePreference; label: string }[] = [
  { value: 'system', label: 'settings.themeSystem' },
  { value: 'light', label: 'settings.themeLight' },
  { value: 'dark', label: 'settings.themeDark' },
];

/** Advanced feature toggle rows of the General pane (1Password-style: off by default, opt-in) */
const FEATURE_ROWS: {
  key: keyof FeatureFlags;
  label: string;
  hint: string;
  /** Extra note such as needing to re-unlock for the toggle to take effect */
  note?: string;
}[] = [
  { key: 'ssh_agent', label: 'settings.advanced.sshAgentLabel', hint: 'settings.advanced.sshAgentHint' },
  { key: 'wallet', label: 'settings.advanced.walletLabel', hint: 'settings.advanced.walletHint' },
  {
    key: 'passkeys',
    label: 'settings.advanced.passkeysLabel',
    hint: 'settings.advanced.passkeysHint',
    note: 'settings.advanced.passkeysNote',
  },
  {
    key: 'fetch_favicons',
    label: 'settings.advanced.fetchFaviconsLabel',
    hint: 'settings.advanced.fetchFaviconsHint',
    note: 'settings.advanced.fetchFaviconsNote',
  },
];

const GeneralPane: React.FC<{
  changingPassword: boolean;
  setChangingPassword: (open: boolean) => void;
}> = ({ changingPassword, setChangingPassword }) => {
  const { t } = useTranslation();
  const featureFlags = useAppStore((s) => s.featureFlags);
  const setFeatureFlags = useAppStore((s) => s.setFeatureFlags);
  const theme = useAppStore((s) => s.theme);
  const setTheme = useAppStore((s) => s.setTheme);

  const [locale, setLocale] = useState(i18n.language.startsWith('en') ? 'en' : 'zh-CN');
  // Serialized write chain: the next write is sent only after the previous one settles (2026-11-13
  // deep-review Major fix: concurrent writes each carry a stale baseline, and a late failure would
  // knock back a later write that had succeeded).
  const localeChain = useRef<Promise<void>>(Promise.resolve());
  const localeRef = useRef(locale);
  const flagsChain = useRef<Promise<void>>(Promise.resolve());

  // Locale switch: optimistic — swap the rendering language first, then persist; roll back on failure (both UI and i18n)
  const changeLocale = (next: string) => {
    const run = async () => {
      const previous = localeRef.current;
      localeRef.current = next;
      setLocale(next);
      void i18n.changeLanguage(next);
      try {
        const resp = await personaAPI.setLocale(next);
        if (!resp.success) {
          localeRef.current = previous;
          setLocale(previous);
          void i18n.changeLanguage(previous);
          toast.error(resp.error || t('settings.saveFailed'));
          return;
        }
        // Switch the tray context-menu copy along with it (the native menu goes through set_tray_locale,
        // no parallel mechanism); use the global i18n.t to read the post-switch language — the component-level
        // t is a getFixedT snapshot of the old language
        void personaAPI.setTrayLocale(trayLocaleLabels((key) => i18n.t(key)));
      } catch (err) {
        localeRef.current = previous;
        setLocale(previous);
        void i18n.changeLanguage(previous);
        toast.error(err instanceof Error ? err.message : t('settings.saveFailed'));
      }
    };
    localeChain.current = localeChain.current.then(run, run);
  };

  // Optimistic write → backfill from server truth; on failure roll back and toast. The baseline is the
  // latest store value taken inside the chain (possibly refreshed by the previous write's successful
  // backfill); a failure rolls back only its own write.
  const toggle = (key: keyof FeatureFlags) => {
    const run = async () => {
      const previous = useAppStore.getState().featureFlags;
      const next = { ...previous, [key]: !previous[key] };
      setFeatureFlags(next);

      try {
        const resp = await personaAPI.setFeatureFlags(next);
        if (resp.success && resp.data) {
          setFeatureFlags(resp.data.features);
        } else {
          setFeatureFlags(previous);
          toast.error(resp.error || t('settings.saveFailed'));
        }
      } catch (err) {
        setFeatureFlags(previous);
        toast.error(err instanceof Error ? err.message : t('settings.saveFailed'));
      }
    };
    flagsChain.current = flagsChain.current.then(run, run);
  };

  return (
    <div>
      {/* S5-b data-loss hard warning: a persistent banner on the settings page (red dot); it clears
          automatically once either a second device or a backup credential is in place; account binding is one tier lower */}
      <DataLossWarning variant="banner" />
      <section className="mb-5">
        <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">{t('settings.theme')}</h3>
        <div
          className="flex bg-gray-100 rounded-lg p-1 dark:bg-gray-800"
          role="radiogroup"
          aria-label={t('settings.theme')}
        >
          {THEME_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              role="radio"
              aria-checked={theme === opt.value}
              data-testid={`theme-option-${opt.value}`}
              onClick={() => setTheme(opt.value)}
              className={`whitespace-nowrap flex-1 px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                theme === opt.value
                  ? 'bg-white text-gray-900 shadow-sm dark:bg-gray-700 dark:text-gray-100'
                  : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
              }`}
            >
              {t(opt.label)}
            </button>
          ))}
        </div>
      </section>

      <section className="mb-5">
        <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">{t('settings.language')}</h3>
        <select
          data-testid="locale-select"
          aria-label={t('settings.language')}
          value={locale}
          onChange={(e) => changeLocale(e.target.value)}
          className="input max-w-[14rem]"
        >
          {/* Language names are written in their own native names (i18n convention, not translated with the UI language) */}
          <option value="zh-CN">简体中文</option>
          <option value="en">English</option>
        </select>
      </section>

      <section className="mb-5">
        <QuickAccessSection />
      </section>

      <section className="mb-5">
        <GeneratorHotkeySection />
      </section>

      <section className="mb-5">
        <UpdateCheckSection />
      </section>

      <section className="mb-5">
        <SyncMethodsSection />
      </section>

      <section className="mb-5">
        <SyncTransportSection />
      </section>

      <section className="mb-5">
        <SyncServerPane />
      </section>

      <section className="mb-5">
        <SyncDevicesSection />
      </section>

      <section className="mb-5">
        <SyncGroupSection />
      </section>

      <section className="mb-5">
        <AccountSection />
      </section>

      <section className="mb-5">
        <SecurityPane
          changingPassword={changingPassword}
          setChangingPassword={setChangingPassword}
        />
      </section>

      <section className="mb-5">
        <BackupSection />
      </section>

      <section className="mb-5">
        <ConnectAutomationSection />
      </section>

      <section className="mb-5">
        <SshIntegrationSection />
      </section>

      <section>
        <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
          {t('settings.advanced.title')}
        </h3>
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
          {t('settings.advanced.description')}
        </p>
        <div className="border border-gray-200 rounded-lg divide-y divide-gray-100 dark:border-gray-700 dark:divide-gray-800">
          {FEATURE_ROWS.map((row) => (
            <div key={row.key} className="flex items-center justify-between gap-4 px-4 py-3">
              <div className="min-w-0">
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100">{t(row.label)}</p>
                <p className="text-xs text-gray-500 dark:text-gray-400">{t(row.hint)}</p>
                {row.note && (
                  <p className="text-xs text-gray-400 dark:text-gray-500">{t(row.note)}</p>
                )}
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={featureFlags[row.key]}
                aria-label={t(row.label)}
                data-testid={`feature-toggle-${row.key}`}
                onClick={() => toggle(row.key)}
                className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors ${
                  featureFlags[row.key] ? 'bg-primary-600' : 'bg-gray-200 dark:bg-gray-700'
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
      </section>
    </div>
  );
};


export default GeneralPane;
