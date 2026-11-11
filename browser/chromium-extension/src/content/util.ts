import type { DetectedForm } from '../formScanner.js';

// Frame role (batch B: the content script now runs in every frame).
// `window.top` throws on cross-origin parents, hence the guarded read. Frame
// forms fill themselves — each frame talks to the bridge with its OWN origin,
// which is exactly what the origin binding checks. Only page-level chrome
// (the Ctrl+Shift+P overlay, the post-navigation save-bar restore) belongs to
// the top frame, or one bar/overlay per frame would appear.
export const IS_TOP_FRAME = (() => {
    try {
        return window.top === window;
    } catch {
        return false;
    }
})();

export function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}


export function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}


export function hasValue(input: HTMLInputElement | null | undefined): boolean {
    return Boolean(input?.value?.trim());
}


export function fillInput(input: HTMLInputElement, value: string) {
    // Focus the input
    input.focus();

    // Set value
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype, 'value'
    )?.set;

    if (nativeInputValueSetter) {
        nativeInputValueSetter.call(input, value);
    } else {
        input.value = value;
    }

    // Dispatch events to trigger React/Vue/Angular handlers
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
}

// Handle fill command from popup
