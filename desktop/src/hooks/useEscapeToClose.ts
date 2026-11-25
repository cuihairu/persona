import { useEffect, useRef } from 'react';

/**
 * Escape closes the modal: listens on window keydown (focus does not need to be inside the modal,
 * matching 1Password—Esc closes whenever the modal is open). When isOpen=false no listener is attached.
 *
 * onClose goes through a latest-ref (following useGlobalShortcut), so the listener is only rebuilt when
 * isOpen changes; stacked modals are coordinated by the caller: the lower modal passes
 * `isOpen && !upperModalOpen` so Esc only closes the topmost one.
 */
export const useEscapeToClose = (isOpen: boolean, onClose: () => void) => {
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCloseRef.current();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen]);
};
