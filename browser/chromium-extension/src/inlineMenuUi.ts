/**
 * Inline menu DOM: rendering, positioning and keyboard interaction for the
 * 1Password-style focus menu (candidates listed on field focus, picked by
 * click or Enter — never auto-filled). Lives at the src root on purpose:
 * content bundles it (esbuild) AND extension pages can import the emitted
 * module for real-browser walkthroughs; dist/content is a build-cleanup
 * casualty, so nothing may depend on files under it.
 */

import { isNavKey, steppedIndex } from './popupNav.js';
import type { InlineCandidate } from './inlineMenu.js';

export interface FieldRect {
    top: number;
    bottom: number;
    left: number;
    height: number;
}

export interface MenuSize {
    width: number;
    height: number;
}

export interface ViewportSpec {
    innerWidth: number;
    innerHeight: number;
}

export interface MenuPosition {
    left: number;
    top: number;
    /** 'below' = under the field, 'above' = flipped over it */
    placement: 'below' | 'above';
}

export const MENU_GAP_PX = 4;

/**
 * Field-proximity positioning with viewport flip: prefer below the field;
 * when the menu would overflow the bottom (and there is more room above),
 * flip above. Horizontal position is clamped into the viewport. Inputs are
 * document coordinates, the result is too (caller adds scroll offsets).
 */
export function computeMenuPosition(
    field: FieldRect,
    menu: MenuSize,
    viewport: ViewportSpec,
    gap: number = MENU_GAP_PX
): MenuPosition {
    const below = field.bottom + gap;
    const fitsBelow = below + menu.height <= viewport.innerHeight;
    let top: number;
    let placement: 'below' | 'above';
    if (fitsBelow || field.top - gap - menu.height < 0) {
        top = Math.max(0, Math.min(below, viewport.innerHeight - menu.height));
        placement = 'below';
    } else {
        top = field.top - gap - menu.height;
        placement = 'above';
    }
    const left = Math.max(0, Math.min(field.left, viewport.innerWidth - menu.width));
    return { left, top, placement };
}

export interface InlineMenuHandle {
    el: HTMLElement;
    /** current selection index (-1 = none yet) */
    selectedIndex: () => number;
    close: () => void;
}

export interface InlineMenuOptions {
    /** document coordinates of the field (getBoundingClientRect + scroll) */
    field: FieldRect;
    /** container the menu mounts into (shadow root in production) */
    mount: ParentNode;
    /** document to attach global listeners to (default: mount's document) */
    doc?: Document;
    /** picks an item (click or Enter); the menu closes afterwards */
    onPick: (candidate: InlineCandidate) => void;
    /** header title; defaults to the product name */
    title?: string;
    /** the focused field: closing on blur (pointer over the menu survives) */
    fieldEl?: HTMLElement;
    menuWidth?: number;
}

const OPTION_ID_PREFIX = 'persona-inline-opt-';

/**
 * Render the candidate menu for a field: a listbox with per-option ids,
 * aria-activedescendant selection, arrow/Enter/Escape/Home/End keyboard
 * control, and close-on click-outside/Escape/scroll/field-blur. Pure DOM —
 * callers own where candidates come from and what picking does.
 */
export function renderInlineMenu(
    candidates: readonly InlineCandidate[],
    options: InlineMenuOptions
): InlineMenuHandle {
    const doc = options.doc ?? (options.mount as Element).ownerDocument;
    const menuWidth = options.menuWidth ?? 280;
    const schedule = doc.defaultView?.setTimeout.bind(doc.defaultView) ?? setTimeout;

    const menu = doc.createElement('div');
    menu.className = 'persona-dropdown p-panel';
    menu.setAttribute('role', 'listbox');
    menu.setAttribute('aria-label', options.title ?? 'Persona suggestions');
    menu.style.cssText = `position: absolute; z-index: 999999; width: ${menuWidth}px; max-height: 300px; overflow-y: auto;`;

    const header = doc.createElement('div');
    header.className = 'p-plain-head';
    header.textContent = options.title ?? 'Persona';
    menu.appendChild(header);

    const optionEls: HTMLElement[] = [];
    candidates.forEach((candidate, index) => {
        const item = doc.createElement('div');
        item.className = 'p-item';
        item.id = `${OPTION_ID_PREFIX}${index}`;
        item.setAttribute('role', 'option');
        item.setAttribute('aria-selected', 'false');
        const t = doc.createElement('div');
        t.className = 't';
        t.textContent = candidate.title;
        const s = doc.createElement('div');
        s.className = 's';
        s.textContent = candidate.username_hint || '';
        item.appendChild(t);
        item.appendChild(s);
        item.addEventListener('click', () => pick(index));
        menu.appendChild(item);
        optionEls.push(item);
    });

    const place = () => {
        const size = { width: menu.offsetWidth || menuWidth, height: menu.offsetHeight || 200 };
        const viewport = {
            innerWidth: doc.documentElement.clientWidth || doc.defaultView?.innerWidth || 1024,
            innerHeight: doc.documentElement.clientHeight || doc.defaultView?.innerHeight || 768
        };
        const pos = computeMenuPosition(options.field, size, viewport);
        menu.style.left = `${pos.left + (doc.defaultView?.scrollX ?? 0)}px`;
        menu.style.top = `${pos.top + (doc.defaultView?.scrollY ?? 0)}px`;
    };
    place();

    let selected = -1;
    const applySelection = () => {
        optionEls.forEach((el, index) => {
            el.setAttribute('aria-selected', index === selected ? 'true' : 'false');
            el.classList.toggle('p-item-active', index === selected);
        });
        if (selected >= 0) {
            menu.setAttribute('aria-activedescendant', `${OPTION_ID_PREFIX}${selected}`);
            // jsdom (tests) has no scrollIntoView; real browsers always do
            optionEls[selected].scrollIntoView?.({ block: 'nearest' });
        } else {
            menu.removeAttribute('aria-activedescendant');
        }
    };

    let closed = false;
    const close = () => {
        if (closed) return;
        closed = true;
        menu.remove();
        doc.removeEventListener('keydown', onKeydown, true);
        doc.removeEventListener('scroll', onScroll, true);
    };

    const pick = (index: number) => {
        close();
        const candidate = candidates[index];
        if (candidate) options.onPick(candidate);
    };

    const onKeydown = (event: KeyboardEvent) => {
        if (event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            close();
            return;
        }
        if (!isNavKey(event.key)) return;
        const count = optionEls.length;
        if (event.key === 'Enter') {
            if (selected >= 0) {
                event.preventDefault();
                pick(selected);
            }
            return;
        }
        if (event.key === 'Home') {
            event.preventDefault();
            selected = count > 0 ? 0 : -1;
            applySelection();
            return;
        }
        if (event.key === 'End') {
            event.preventDefault();
            selected = count - 1;
            applySelection();
            return;
        }
        event.preventDefault();
        selected = steppedIndex(count, selected, event.key === 'ArrowDown' ? 1 : -1);
        applySelection();
    };

    // capture: the page sees neither the nav keys (no scroll) nor Escape
    const onScroll = () => close();

    doc.addEventListener('keydown', onKeydown, true);
    doc.addEventListener('scroll', onScroll, true);

    // the field losing focus closes the menu — unless the pointer is on it
    // (moving toward an item) or the blur IS the menu interaction itself
    if (options.fieldEl) {
        const onFieldBlur = () => {
            schedule(() => {
                if (!closed && !menu.matches(':hover')) close();
            }, 150);
        };
        options.fieldEl.addEventListener('blur', onFieldBlur, { once: true });
    }

    // click outside (everything under the closed shadow root retargets, so
    // any click the document sees beyond the menu itself is outside). The
    // short grace window keeps the opening click from dismissing the menu.
    schedule(() => {
        doc.addEventListener('click', function onOutsideClick(e) {
            if (closed) {
                doc.removeEventListener('click', onOutsideClick);
                return;
            }
            if (!menu.contains(e.target as Node)) {
                close();
                doc.removeEventListener('click', onOutsideClick);
            }
        });
    }, 100);

    options.mount.appendChild(menu);
    return { el: menu, selectedIndex: () => selected, close };
}
