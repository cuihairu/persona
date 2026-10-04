// Multi-step login decision (pure). Batch B of the browser-extension track.
//
// Many sites split a login across pages/frames: step 1 asks for the username
// only, step 2 (a fresh document, so a fresh content script) asks for the
// password. Today the extension only acts when a password field is present,
// so step 1 was manual. This module decides what a frame should do with a
// form on its own, with no DOM or chrome APIs involved:
//
//   'credentials' → username + password (the pre-existing behaviour)
//   'username'    → username only (step 1 of a multi-step login)
//   'wait'        → do nothing automatically
//
// Safety rules encoded here, all of them about *not* putting a username into
// a field that isn't an identity field:
//
// - Load-triggered username fills require the field to announce itself: an
//   explicit `autocomplete="username"/"email"`, or a name/id the scanner
//   resolved to its `username` bucket. A `type=email` box is
//   indistinguishable from a newsletter signup, so it waits for a click.
// - Nothing happens when the field already has a value — the site's
//   prefilled/typed username wins.
// - A username is only auto-filled when the suggestion is *resolvable*
//   (exactly one candidate for this origin, or a unique match against what
//   the user typed, or this origin's remembered default item). Guessing among
//   several accounts on page load is how you type the wrong identity into
//   someone else's account picker.

export type LoginStepAction = 'credentials' | 'username' | 'wait';

export interface IdentityFieldInfo {
    /** How the form scanner classified the field. */
    kind: 'username' | 'email' | 'text' | 'password' | 'none';
    /** The field's own `autocomplete` attribute, lowercased ('' when absent). */
    autocomplete: string;
    hasValue: boolean;
    /** True when this field is the one the user just focused. */
    isFocused: boolean;
}

export interface LoginStepInput {
    trigger: 'load' | 'focus';
    hasPasswordField: boolean;
    identityField: IdentityFieldInfo | null;
    /** `selectLoginSuggestion()` resolved exactly one item for this origin. */
    hasResolvableSuggestion: boolean;
}

export function planLoginStep(input: LoginStepInput): LoginStepAction {
    if (!input.hasResolvableSuggestion) return 'wait';

    // A password field in view means the ordinary one-shot fill applies; the
    // username-only branch is only for forms that have no password yet.
    if (input.hasPasswordField) return 'credentials';

    const field = input.identityField;
    if (!field || field.hasValue) return 'wait';
    if (field.kind === 'password' || field.kind === 'none') return 'wait';

    if (input.trigger === 'focus') {
        // Focused by the user: any scanner-recognized identity field counts.
        return field.isFocused ? 'username' : 'wait';
    }

    // Page load: only fields that clearly announce themselves as identity
    // inputs — an explicit `autocomplete="username"/"email"`, or a name/id
    // that resolves to the scanner's `username` bucket (login/user/
    // identifier/account hints). A bare `type=email` or `name=email` box is
    // indistinguishable from a newsletter signup at load time, so it waits
    // for a click.
    const announced = field.autocomplete === 'username' || field.autocomplete === 'email';
    return announced || field.kind === 'username' ? 'username' : 'wait';
}