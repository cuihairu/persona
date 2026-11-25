import { useCallback, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '@/utils/api';

/**
 * A promise-based reauthentication flow:
 * `const ok = await requestReauth()` opens the prompt and suspends,
 * resolving with true once the password verifies, and false on cancel/close.
 *
 * Typical usage (when catching error_code === 'REAUTH_REQUIRED'):
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
