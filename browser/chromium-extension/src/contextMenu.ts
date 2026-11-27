// Right-click menu wiring, kept as pure data so the builder and the click
// router stay testable without a service-worker environment. Menu ids encode
// both the action and the credential kind: `persona-fill:<kind>:<item_id>`.

export const MENU_ROOT_ID = 'persona-root';
export const MENU_POPUP_ID = 'persona-open-popup';
export const MENU_FILL_PREFIX = 'persona-fill:';
export const MENU_COPY_PREFIX = 'persona-copy:';

/** Items above this never make it into the menu: right-click lists stay scannable. */
export const MENU_SUGGESTION_CAP = 8;

export interface MenuSuggestion {
    item_id: string;
    title: string;
    credential_type?: string;
}

export interface MenuEntry {
    id: string;
    title: string;
    parentId?: string;
}

export type MenuAction =
    | { action: 'fill'; kind: 'password' | 'totp' | 'card'; itemId: string }
    | { action: 'copy'; kind: 'password' | 'totp'; itemId: string }
    | { action: 'popup' };

function menuKind(credentialType?: string): 'password' | 'totp' | 'card' {
    const kind = (credentialType ?? '').toLowerCase();
    if (kind.includes('totp') || kind.includes('otp')) return 'totp';
    if (kind.includes('card')) return 'card';
    return 'password';
}

export function buildMenuEntries(suggestions: MenuSuggestion[]): MenuEntry[] {
    const entries: MenuEntry[] = [{ id: MENU_ROOT_ID, title: 'Persona' }];

    for (const suggestion of suggestions.slice(0, MENU_SUGGESTION_CAP)) {
        const kind = menuKind(suggestion.credential_type);
        if (kind === 'password') {
            entries.push({ id: `${MENU_FILL_PREFIX}password:${suggestion.item_id}`, title: `Fill: ${suggestion.title}`, parentId: MENU_ROOT_ID });
            entries.push({ id: `${MENU_COPY_PREFIX}password:${suggestion.item_id}`, title: `Copy password: ${suggestion.title}`, parentId: MENU_ROOT_ID });
        } else if (kind === 'totp') {
            entries.push({ id: `${MENU_FILL_PREFIX}totp:${suggestion.item_id}`, title: `Fill 2FA code: ${suggestion.title}`, parentId: MENU_ROOT_ID });
            entries.push({ id: `${MENU_COPY_PREFIX}totp:${suggestion.item_id}`, title: `Copy 2FA code: ${suggestion.title}`, parentId: MENU_ROOT_ID });
        } else {
            // cards have no copyable secret through the menu (CVV keeps its
            // copy-only popup path)
            entries.push({ id: `${MENU_FILL_PREFIX}card:${suggestion.item_id}`, title: `Fill: ${suggestion.title}`, parentId: MENU_ROOT_ID });
        }
    }

    entries.push({ id: MENU_POPUP_ID, title: 'Open Persona popup', parentId: MENU_ROOT_ID });
    return entries;
}

export function parseMenuAction(id: string): MenuAction | null {
    if (id === MENU_POPUP_ID) return { action: 'popup' };
    if (id.startsWith(MENU_FILL_PREFIX)) {
        const rest = id.slice(MENU_FILL_PREFIX.length);
        const sep = rest.indexOf(':');
        if (sep <= 0) return null;
        const kind = rest.slice(0, sep);
        const itemId = rest.slice(sep + 1);
        if (kind === 'password' || kind === 'totp' || kind === 'card') {
            return { action: 'fill', kind, itemId };
        }
        return null;
    }
    if (id.startsWith(MENU_COPY_PREFIX)) {
        const rest = id.slice(MENU_COPY_PREFIX.length);
        const sep = rest.indexOf(':');
        if (sep <= 0) return null;
        const kind = rest.slice(0, sep);
        const itemId = rest.slice(sep + 1);
        if (kind === 'password' || kind === 'totp') {
            return { action: 'copy', kind, itemId };
        }
        return null;
    }
    return null;
}
