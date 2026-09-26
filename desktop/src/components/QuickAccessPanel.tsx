import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { MagnifyingGlassIcon, LockClosedIcon } from '@heroicons/react/24/outline';
import toast, { Toaster } from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { listen } from '@tauri-apps/api/event';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useReauth } from '@/hooks/useReauth';
import { useAppStore } from '@/stores/appStore';
import { personaAPI } from '@/utils/api';
import { copyToClipboardWithToast } from '@/utils/clipboard';
import { credentialTypeLabel, getCredentialIcon } from './credentialDisplay';
import FaviconImg from './FaviconImg';
import Highlight from './Highlight';
import ReauthModal from './ReauthModal';
import type { Credential, Identity, SecretField } from '@/types';

/** 后端唤醒事件（quick_access.rs OPENED_EVENT）：热键唤起时清查询 + 重新探解锁态 */
const OPENED_EVENT = 'persona://quick-access-opened';
/** 锁户事件（主窗口侧锁定 / auto-lock 到期都发这个）：浮窗立刻收起 */
const AUTO_LOCK_EVENT = 'persona://auto-lock';
/** 输入停顿 200ms 才发起后端搜索（同 QuickSearch：本地 SQLite LIKE） */
const DEBOUNCE_MS = 200;

/**
 * 凭据类型 → Enter 键复制的敏感字段。
 *
 * 只覆盖后端 `extract_secret_field` 真正支持的组合（Password / ApiKey /
 * SshKey / CryptoWallet）；其余类型（银行卡、身份、许可证、SecureNote…）
 * 在详情面板里本来就没有单字段揭示入口，这里返回 null —— 面板只提供
 * "复制用户名 / 复制 TOTP / 在 Persona 中打开"，不假装能取到密文。
 */
const primarySecretField = (type: string): SecretField | null => {
  switch (type) {
    case 'Password':
      return 'password';
    case 'ApiKey':
      return 'api_key';
    case 'SshKey':
      return 'ssh_private_key';
    case 'CryptoWallet':
      return 'wallet_private_key';
    default:
      return null;
  }
};

/** 按 identities 顺序把命中结果归到各身份名下（组内保持后端 created_at DESC 序） */
const groupByIdentity = (
  results: Credential[],
  identities: Identity[],
): { identity: Identity; items: Credential[] }[] => {
  const byIdentity = new Map<string, Credential[]>();
  for (const cred of results) {
    const list = byIdentity.get(cred.identity_id) ?? [];
    list.push(cred);
    byIdentity.set(cred.identity_id, list);
  }
  return identities
    .map((identity) => ({ identity, items: byIdentity.get(identity.id) ?? [] }))
    .filter((group) => group.items.length > 0);
};

/** 非 Tauri 环境（jest/jsdom）下 getCurrentWindow 同步抛错，隐藏动作降级为空操作 */
const hideSelf = async () => {
  try {
    await getCurrentWindow().hide();
  } catch {
    // jsdom / 非 Tauri 环境：__TAURI_INTERNALS__ 缺失
  }
};

/**
 * Quick Access 浮窗（对标矩阵 #22）：OS 级全局热键唤起的跨身份检索面。
 *
 * 键位（与 i18n 提示行一致）：
 * - ↑/↓ 移动、Enter 复制主密文（无密文字段时退回复制用户名）
 * - ⌘/Ctrl+U 复制用户名、⌘/Ctrl+T 复制 TOTP、⌘/Ctrl+O 在 Persona 中打开
 * - Esc 收起
 *
 * 锁定态刻意**不复刻解锁流**（小窗里塞解锁屏 + 生物弹框体验很差，且
 * 跨窗口会话同步要另开通道）：只提示并把主窗口拉到前台。
 */
const QuickAccessPanel: React.FC = () => {
  const { t } = useTranslation();
  const { isUnlocked, searchCredentials, checkServiceStatus } = usePersonaService();
  const identities = useAppStore((s) => s.identities);
  const reauth = useReauth();

  const [query, setQuery] = useState('');
  const [results, setResults] = useState<Credential[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const [copied, setCopied] = useState<string | null>(null);

  const inputRef = useRef<HTMLInputElement>(null);
  const searchRef = useRef(searchCredentials);
  searchRef.current = searchCredentials;
  const checkRef = useRef(checkServiceStatus);
  checkRef.current = checkServiceStatus;

  const groups = useMemo(() => groupByIdentity(results, identities), [results, identities]);
  const flatResults = useMemo(() => groups.flatMap((group) => group.items), [groups]);
  const active = flatResults[Math.min(activeIndex, Math.max(flatResults.length - 1, 0))];

  const reset = useCallback(() => {
    setQuery('');
    setResults([]);
    setIsSearching(false);
    setActiveIndex(0);
    setCopied(null);
  }, []);

  // 唤醒通道：热键每次唤起都要重新探解锁态（主窗口的解锁/锁定本窗口收不到
  // 事件通知，store 又是每窗口一份）+ 清掉上一次的查询
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    try {
      const pending = listen(OPENED_EVENT, () => {
        void checkRef.current();
        reset();
        // 等下一帧再聚焦：show() 之后 webview 才拿到键盘焦点
        window.setTimeout(() => inputRef.current?.focus(), 50);
      });
      // rejection handler 吃掉非 Tauri 环境的 listen 失败（同 useQuickAccessBridge）
      pending.then(
        (fn) => {
          if (cancelled) fn();
          else unlisten = fn;
        },
        () => {},
      );
    } catch {
      // 非 Tauri 环境无 listen
    }
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [reset]);

  // 锁户（含主窗口锁定与 auto-lock 到期）→ 浮窗立刻收起，不留检索结果在屏上
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    try {
      const pending = listen(AUTO_LOCK_EVENT, () => {
        void hideSelf();
      });
      pending.then(
        (fn) => {
          if (cancelled) fn();
          else unlisten = fn;
        },
        () => {},
      );
    } catch {
      // 非 Tauri 环境无 listen
    }
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  // debounce 搜索；空查询直接清结果不发请求
  useEffect(() => {
    const trimmed = query.trim();
    if (!isUnlocked || !trimmed) {
      setResults([]);
      setIsSearching(false);
      return;
    }
    setIsSearching(true);
    const timer = window.setTimeout(async () => {
      setResults(await searchRef.current(trimmed));
      setIsSearching(false);
    }, DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [query, isUnlocked]);

  /** 揭示 + 复制一个敏感字段；REAUTH_REQUIRED 走 ReauthModal 重试一次 */
  const copySecret = useCallback(
    async (credential: Credential, field: SecretField) => {
      const reveal = async (): Promise<string | null> => {
        const res = await personaAPI.revealCredentialSecret(credential.id, field);
        if (res.success && res.data) return res.data.value;
        if (res.error_code === 'REAUTH_REQUIRED') {
          if (await reauth.requestReauth()) return reveal();
          return null;
        }
        if (res.error_code === 'SERVICE_LOCKED') {
          toast.error(t('common.serviceLocked'));
          return null;
        }
        toast.error(res.error ?? t('reveal.failed'));
        return null;
      };

      const value = await reveal();
      if (value === null) return;
      await copyToClipboardWithToast(value, t('quickAccess.password'));
      setCopied(`${credential.id}:${field}`);
      window.setTimeout(() => setCopied(null), 2000);
    },
    [reauth, t],
  );

  const copyUsername = useCallback(
    (credential: Credential) => {
      if (!credential.username) {
        toast.error(t('app.noUsername'));
        return;
      }
      void copyToClipboardWithToast(credential.username, t('app.username'));
      setCopied(`${credential.id}:username`);
      window.setTimeout(() => setCopied(null), 2000);
    },
    [t],
  );

  const copyTotp = useCallback(
    async (credential: Credential) => {
      const res = await personaAPI.getTotpCode(credential.id);
      if (res.success && res.data) {
        await copyToClipboardWithToast(res.data.code, t('quickAccess.totp'));
        setCopied(`${credential.id}:totp`);
        window.setTimeout(() => setCopied(null), 2000);
      } else {
        toast.error(res.error ?? t('svc.totpFailed'));
      }
    },
    [t],
  );

  const openInPersona = useCallback(
    async (credential: Credential) => {
      const res = await personaAPI.quickAccessOpenCredential(credential.identity_id, credential.id);
      if (!res.success) {
        toast.error(res.error ?? t('quickAccess.openFailed'));
      }
    },
    [t],
  );

  /** Enter：优先复制主密文字段，没有则退回复制用户名（面板不猜别的密文字段） */
  const copyPrimary = useCallback(
    (credential: Credential) => {
      const field = primarySecretField(credential.credential_type);
      if (field) {
        void copySecret(credential, field);
      } else {
        copyUsername(credential);
      }
    },
    [copySecret, copyUsername],
  );

  const onKeyDown = (event: React.KeyboardEvent) => {
    const total = flatResults.length;
    const mod = event.metaKey || event.ctrlKey;

    if (event.key === 'Escape') {
      event.preventDefault();
      void hideSelf();
      return;
    }
    if (!active) return;

    if (event.key === 'ArrowDown' && total > 0) {
      event.preventDefault();
      setActiveIndex((index) => (index + 1) % total);
    } else if (event.key === 'ArrowUp' && total > 0) {
      event.preventDefault();
      setActiveIndex((index) => (index - 1 + total) % total);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      copyPrimary(active);
    } else if (mod && event.key.toLowerCase() === 'u') {
      // ⌘U 不与输入框的原生行为冲突（⌘C 会与文本选择冲突，故不用）
      event.preventDefault();
      copyUsername(active);
    } else if (mod && event.key.toLowerCase() === 't') {
      event.preventDefault();
      void copyTotp(active);
    } else if (mod && event.key.toLowerCase() === 'o') {
      event.preventDefault();
      void openInPersona(active);
    }
  };

  if (!isUnlocked) {
    return (
      <div
        className="h-screen w-screen bg-white dark:bg-gray-900 flex flex-col items-center justify-center gap-3 px-6 text-center"
        data-testid="quick-access-locked"
      >
        <LockClosedIcon className="w-8 h-8 text-gray-400 dark:text-gray-500" />
        <p className="text-sm text-gray-600 dark:text-gray-300">{t('quickAccess.lockedHint')}</p>
        <button
          type="button"
          data-testid="quick-access-unlock-button"
          onClick={() => void personaAPI.focusMainWindow()}
          className="rounded-md bg-primary-600 hover:bg-primary-700 text-white text-sm px-4 py-2"
        >
          {t('quickAccess.openMainWindow')}
        </button>
        <Toaster position="top-center" toastOptions={{ className: 'persona-toast' }} />
      </div>
    );
  }

  return (
    <div
      className="h-screen w-screen bg-white dark:bg-gray-900 flex flex-col overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700"
      onKeyDown={onKeyDown}
      data-testid="quick-access-panel"
    >
      <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-200 dark:border-gray-700 shrink-0">
        <MagnifyingGlassIcon className="w-4 h-4 shrink-0 text-gray-400 dark:text-gray-500" />
        <input
          ref={inputRef}
          type="text"
          autoFocus
          data-testid="quick-access-input"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setActiveIndex(0);
          }}
          placeholder={t('quickAccess.inputPlaceholder')}
          className="w-full bg-transparent outline-none text-sm text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500"
        />
      </div>

      <div className="flex-1 overflow-y-auto py-1" data-testid="quick-access-results">
        {!query.trim() ? (
          <p className="px-4 py-8 text-center text-sm text-gray-400 dark:text-gray-500">
            {t('quickSearch.typeToSearch')}
          </p>
        ) : isSearching && groups.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-gray-400 dark:text-gray-500">
            {t('quickSearch.searching')}
          </p>
        ) : groups.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-gray-400 dark:text-gray-500">
            {t('quickSearch.noResults', { query: query.trim() })}
          </p>
        ) : (
          (() => {
            let flatIndex = -1;
            return groups.map((group) => (
              <div key={group.identity.id}>
                <div className="px-4 py-1.5 text-xs font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
                  {group.identity.name}
                </div>
                {group.items.map((credential) => {
                  flatIndex += 1;
                  const index = flatIndex;
                  const isActive = index === activeIndex;
                  const TypeIcon = getCredentialIcon(credential.credential_type);
                  return (
                    <button
                      key={credential.id}
                      type="button"
                      data-testid="quick-access-item"
                      data-active={isActive}
                      onClick={() => setActiveIndex(index)}
                      onDoubleClick={() => copyPrimary(credential)}
                      onMouseEnter={() => setActiveIndex(index)}
                      className={`w-full flex items-center gap-3 px-4 py-2 text-left transition-colors ${
                        isActive
                          ? 'bg-primary-50 dark:bg-primary-500/10'
                          : 'hover:bg-gray-50 dark:hover:bg-gray-800'
                      }`}
                    >
                      <FaviconImg
                        url={credential.url}
                        fallbackIcon={TypeIcon}
                        sizeClass="w-4 h-4"
                        className="text-gray-400 dark:text-gray-500"
                      />
                      <span className="text-sm text-gray-900 dark:text-gray-100 truncate">
                        <Highlight text={credential.name} query={query} />
                      </span>
                      {credential.username && (
                        <span className="text-xs text-gray-400 dark:text-gray-500 truncate max-w-[35%]">
                          <Highlight text={credential.username} query={query} />
                        </span>
                      )}
                      <span className="ml-auto flex items-center gap-2 shrink-0">
                        {isActive && primarySecretField(credential.credential_type) && (
                          <kbd className="text-[10px] text-gray-400 dark:text-gray-500">↵</kbd>
                        )}
                        {isActive && (
                          <kbd className="text-[10px] text-gray-400 dark:text-gray-500">⌘O</kbd>
                        )}
                        {copied === `${credential.id}:password` ||
                        copied === `${credential.id}:api_key` ||
                        copied === `${credential.id}:ssh_private_key` ||
                        copied === `${credential.id}:wallet_private_key` ? (
                          <span className="text-[10px] text-green-600 dark:text-green-400">
                            {t('quickAccess.copied')}
                          </span>
                        ) : null}
                        <span className="text-xs text-gray-400 dark:text-gray-500">
                          {credentialTypeLabel(t, credential.credential_type)}
                        </span>
                      </span>
                    </button>
                  );
                })}
              </div>
            ));
          })()
        )}
      </div>

      <div
        className="px-4 py-2 border-t border-gray-200 dark:border-gray-700 text-xs text-gray-400 dark:text-gray-500 shrink-0 flex items-center gap-3"
        data-testid="quick-access-hints"
      >
        <span>{t('quickAccess.hintCopy')}</span>
        <span>{t('quickAccess.hintUsername')}</span>
        <span>{t('quickAccess.hintTotp')}</span>
        <span>{t('quickAccess.hintOpen')}</span>
      </div>

      <ReauthModal
        isOpen={reauth.isOpen}
        error={reauth.error}
        isVerifying={reauth.isVerifying}
        onSubmit={reauth.submit}
        onClose={reauth.cancel}
      />
      <Toaster position="top-center" toastOptions={{ className: 'persona-toast' }} />
    </div>
  );
};

export default QuickAccessPanel;
