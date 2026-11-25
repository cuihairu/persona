import { useEffect } from 'react';
import { listen } from '@tauri-apps/api/event';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { useAppStore } from '@/stores/appStore';
import { personaAPI } from '@/utils/api';
import type { QuickAccessOpenCredential } from '@/types';

/** Floating window -> main window navigation event (quick_access.rs OPEN_CREDENTIAL_EVENT) */
const OPEN_CREDENTIAL_EVENT = 'persona://quick-access-open-credential';

/**
 * Receiver for the Quick Access floating window's cross-window navigation
 * (mounted only in the main window).
 *
 * The two windows have independent JS stores, so the floating window cannot
 * mutate the main window's selection directly; it can only have Rust emit
 * targeted to the main window (while pulling the main window to the
 * foreground). On receipt: write pendingCredentialSelection (switching
 * identity along the way when it crosses identities, injected by
 * CredentialList) — semantically identical to QuickSearch's in-app navigation.
 *
 * If the identity is not in the local list (synced from another machine, or
 * already deleted) **report the error and do not jump**: silently switching to
 * a nonexistent identity only drags the main UI into an empty state.
 */
export const useQuickAccessBridge = () => {
  const { t } = useTranslation();
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;

    const apply = async (payload: QuickAccessOpenCredential) => {
      const { identities, setPendingCredentialSelection, setCurrentIdentity } =
        useAppStore.getState();
      const target = identities.find((identity) => identity.id === payload.identity_id);
      if (!target) {
        return;
      }
      setPendingCredentialSelection({
        identityId: target.id,
        credentialId: payload.credential_id,
      });
      const current = useAppStore.getState().currentIdentity;
      if (!current || current.id !== target.id) {
        setCurrentIdentity(target);
        try {
          await personaAPI.setActiveIdentity(target.id);
        } catch (err) {
          // A failed persist does not block the navigation (the main UI keeps
          // switching on its in-memory state), but the failure must be visible: the
          // workspace active identity still points at the old one, so the CLI and
          // browser keep operating on it — a silent success would tell the caller
          // the global switch already happened (same rule as switchIdentity)
          const errorMessage = err instanceof Error ? err.message : t('svc.switchFailed');
          useAppStore.getState().setError(errorMessage);
          toast.error(errorMessage);
        }
      }
    };

    try {
      const pending = listen<QuickAccessOpenCredential>(OPEN_CREDENTIAL_EVENT, (event) => {
        void apply(event.payload);
      });
      // The second handler swallows the rejection: in non-Tauri environments
      // (jsdom / opened directly in a browser) listen rejects outright, and a
      // dangling rejection pollutes the output of unrelated cases
      pending.then(
        (fn) => {
          if (cancelled) fn();
          else unlisten = fn;
        },
        () => {},
      );
    } catch {
      // Non-Tauri environments (jest/jsdom) have no listen: the main window's single-window case is unaffected
    }

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [t]);
};
