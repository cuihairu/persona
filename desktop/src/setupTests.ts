import '@testing-library/jest-dom';
// i18n base locale is zh-CN: initialized synchronously on module load; component tests assert Chinese copy
import '@/i18n';

// headlessui v2's Listbox close path relies on ResizeObserver (not implemented in jsdom)
if (typeof window !== 'undefined' && !window.ResizeObserver) {
  window.ResizeObserver = class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
}
