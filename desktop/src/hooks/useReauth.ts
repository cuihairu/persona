import { useCallback, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '@/utils/api';

/**
 * Promise 化的重新认证流程：
 * `const ok = await requestReauth()` 打开弹窗并挂起，
 * 用户密码验证成功 → resolve(true)；取消/关闭 → resolve(false)。
 *
 * 典型用法（在捕获到 error_code === 'REAUTH_REQUIRED' 时）：
 *   if (await requestReauth()) retryOriginalOperation();
 */
export const useReauth = () => {
  const { t } = useTranslation();
  const [isOpen, setIsOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const resolveRef = useRef<((ok: boolean) => void) | null>(null);

  const requestReauth = useCallback((): Promise<boolean> => {
    setError(null);
    setIsOpen(true);
    return new Promise<boolean>((resolve) => {
      resolveRef.current = resolve;
    });
  }, [t]);

  const submit = useCallback(async (masterPassword: string) => {
    setIsVerifying(true);
    setError(null);
    try {
      const res = await personaAPI.reauthVerify(masterPassword);
      if (res.success) {
        setIsOpen(false);
        resolveRef.current?.(true);
      } else {
        setError(res.error ?? t('reauth.invalid'));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsVerifying(false);
    }
  }, [t]);

  const cancel = useCallback(() => {
    setIsOpen(false);
    resolveRef.current?.(false);
  }, [t]);

  return { isOpen, error, isVerifying, requestReauth, submit, cancel };
};
