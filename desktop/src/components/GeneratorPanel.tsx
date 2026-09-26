import React, { useMemo, useState } from 'react';
import { ArrowPathIcon, KeyIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import { personaAPI } from '@/utils/api';
import { copyToClipboardWithToast } from '@/utils/clipboard';
import type { GeneratedPasswords } from '@/types';

const MIN_LENGTH = 4;
const MAX_LENGTH = 64;

/** 熵值分档（bits）：颜色 + 标签（阈值与 1Password 的弱/可/强/极强近似） */
const strengthFor = (bits: number): { tone: string; labelKey: string } => {
  if (bits < 40) {
    return { tone: 'bg-red-500', labelKey: 'generator.strength.veryWeak' };
  }
  if (bits < 60) {
    return { tone: 'bg-orange-500', labelKey: 'generator.strength.weak' };
  }
  if (bits < 80) {
    return { tone: 'bg-yellow-500', labelKey: 'generator.strength.fair' };
  }
  if (bits < 110) {
    return { tone: 'bg-green-500', labelKey: 'generator.strength.strong' };
  }
  return { tone: 'bg-emerald-500', labelKey: 'generator.strength.veryStrong' };
};

interface CharsetToggleProps {
  testId: string;
  label: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
}

const CharsetToggle: React.FC<CharsetToggleProps> = ({ testId, label, checked, disabled, onChange }) => (
  <label
    data-testid={testId}
    className={clsx(
      'flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300',
      disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'
    )}
  >
    <input
      type="checkbox"
      checked={checked}
      disabled={disabled}
      onChange={(e) => onChange(e.target.checked)}
      className="h-4 w-4 rounded border-gray-300 dark:border-gray-600 text-primary-600 dark:text-primary-400 focus:ring-primary-500"
    />
    {label}
  </label>
);

/** 密码生成器面板（主航道视图，无需选中身份；生成是纯计算不触碰库）。 */
const GeneratorPanel: React.FC = () => {
  const { t } = useTranslation();
  const [length, setLength] = useState(16);
  const [includeLowercase, setIncludeLowercase] = useState(true);
  const [includeUppercase, setIncludeUppercase] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [pronounceable, setPronounceable] = useState(false);
  const [count, setCount] = useState(3);
  const [result, setResult] = useState<GeneratedPasswords | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const hasLetterSet = includeLowercase || includeUppercase;
  // 可发音需要字母集；随机模式至少一个字符集（core 校验的镜像，提前禁用按钮）
  const canGenerate = pronounceable ? hasLetterSet : hasLetterSet || includeNumbers || includeSymbols;

  const strength = useMemo(
    () => strengthFor(result?.entropy_bits ?? 0),
    [result]
  );

  const handleGenerate = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await personaAPI.generatePasswordAdvanced({
        length,
        include_lowercase: includeLowercase,
        include_uppercase: includeUppercase,
        include_numbers: includeNumbers,
        include_symbols: includeSymbols,
        pronounceable,
        count,
      });
      if (res.success && res.data) {
        setResult(res.data);
      } else {
        setResult(null);
        setError(res.error ?? t('generator.generateFailed'));
      }
    } catch (e) {
      setResult(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <section className="bg-white dark:bg-gray-900 shadow rounded-xl p-6 border border-gray-100 dark:border-gray-800">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div>
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{t('generator.title')}</p>
            <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">{t('generator.description')}</p>
          </div>
          <button
            data-testid="generator-generate"
            onClick={handleGenerate}
            disabled={isLoading || !canGenerate}
            className="btn-primary inline-flex items-center self-start md:self-auto"
          >
            {result ? (
              <ArrowPathIcon className="w-4 h-4 mr-1" />
            ) : (
              <KeyIcon className="w-4 h-4 mr-1" />
            )}
            {isLoading ? t('generator.generating') : t('generator.generate')}
          </button>
        </div>

        <div className="mt-6 grid grid-cols-1 gap-6 md:grid-cols-2">
          {/* 长度 */}
          <div>
            <div className="flex items-center justify-between">
              <label htmlFor="generator-length" className="text-sm font-medium text-gray-700 dark:text-gray-300">
                {t('generator.length')}
              </label>
              <span data-testid="generator-length-value" className="text-sm text-gray-500 dark:text-gray-400">
                {length}
              </span>
            </div>
            <input
              id="generator-length"
              data-testid="generator-length-input"
              type="range"
              min={MIN_LENGTH}
              max={MAX_LENGTH}
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
              className="mt-2 w-full accent-primary-600 dark:accent-primary-400"
            />
          </div>

          {/* 候选数量 */}
          <div>
            <label htmlFor="generator-count" className="text-sm font-medium text-gray-700 dark:text-gray-300">
              {t('generator.count')}
            </label>
            <select
              id="generator-count"
              data-testid="generator-count-select"
              value={count}
              onChange={(e) => setCount(Number(e.target.value))}
              className="mt-2 w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm text-gray-900 dark:text-gray-100"
            >
              {[1, 3, 5, 10].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>

          {/* 字符集 */}
          <div className="space-y-2 md:col-span-2">
            <p className="text-sm font-medium text-gray-700 dark:text-gray-300">{t('generator.charsets')}</p>
            <div className="flex flex-wrap gap-x-6 gap-y-2">
              <CharsetToggle
                testId="generator-toggle-lowercase"
                label={t('generator.lowercase')}
                checked={includeLowercase}
                onChange={setIncludeLowercase}
              />
              <CharsetToggle
                testId="generator-toggle-uppercase"
                label={t('generator.uppercase')}
                checked={includeUppercase}
                onChange={setIncludeUppercase}
              />
              <CharsetToggle
                testId="generator-toggle-numbers"
                label={t('generator.numbers')}
                checked={includeNumbers}
                onChange={setIncludeNumbers}
              />
              <CharsetToggle
                testId="generator-toggle-symbols"
                label={t('generator.symbols')}
                checked={includeSymbols}
                onChange={setIncludeSymbols}
              />
              <CharsetToggle
                testId="generator-toggle-pronounceable"
                label={t('generator.pronounceable')}
                checked={pronounceable}
                onChange={(checked) => setPronounceable(checked)}
              />
            </div>
            {pronounceable && !hasLetterSet && (
              <p className="text-xs text-amber-600 dark:text-amber-400">{t('generator.pronounceableNeedsLetters')}</p>
            )}
            {!pronounceable && !canGenerate && (
              <p className="text-xs text-amber-600 dark:text-amber-400">{t('generator.needsOneCharset')}</p>
            )}
          </div>
        </div>
      </section>

      {error && (
        <div
          data-testid="generator-error"
          className="rounded-md bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 px-4 py-3 text-sm text-red-800 dark:text-red-300"
        >
          {error}
        </div>
      )}

      {result && (
        <section
          data-testid="generator-results"
          className="bg-white dark:bg-gray-900 shadow rounded-xl border border-gray-100 dark:border-gray-800"
        >
          {/* 熵值计量条 */}
          <div className="p-6 border-b border-gray-100 dark:border-gray-800">
            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-600 dark:text-gray-300">{t('generator.entropy')}</span>
              <span data-testid="generator-entropy-value" className="text-gray-500 dark:text-gray-400">
                {t('generator.entropyValue', {
                  bits: Math.round(result.entropy_bits),
                  pool: result.pool_size,
                })}
              </span>
            </div>
            <div className="mt-2 h-2 w-full rounded-full bg-gray-200 dark:bg-gray-700 overflow-hidden">
              <div
                data-testid="generator-entropy-bar"
                className={clsx('h-full rounded-full transition-all', strength.tone)}
                style={{ width: `${Math.min((result.entropy_bits / 128) * 100, 100)}%` }}
              />
            </div>
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              {t('generator.strengthLabel')}: {t(strength.labelKey)}
            </p>
          </div>

          {/* 候选口令列表 */}
          <ul className="divide-y divide-gray-200 dark:divide-gray-700">
            {result.passwords.map((password, idx) => (
              <li key={`${idx}-${password}`} className="px-6 py-3 flex items-center justify-between gap-4">
                <code data-testid={`generator-password-${idx}`} className="font-mono text-sm text-gray-900 dark:text-gray-100 break-all">
                  {password}
                </code>
                <button
                  data-testid={`generator-copy-${idx}`}
                  onClick={() => void copyToClipboardWithToast(password, t('generator.passwordLabel'))}
                  className="btn-ghost shrink-0"
                >
                  {t('generator.copy')}
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
};

export default GeneratorPanel;
