export type FieldKind =
    | 'password'
    | 'username'
    | 'email'
    | 'totp'
    | 'text'
    // Payment-card fields. Card filling is copy/paste-free except CVV: the
    // bridge never returns CVV, and fillCard deliberately skips card_cvv.
    | 'card_number'
    | 'card_name'
    | 'card_expiry'
    | 'card_cvv';

export interface DetectedField {
    name: string;
    type: FieldKind;
    selector: string;
}

export interface DetectedForm {
    action: string;
    method: string;
    score: number;
    fields: DetectedField[];
}

const USERNAME_HINTS = ['user', 'login', 'identifier'];
const EMAIL_HINTS = ['email', 'mail'];
const TOTP_HINTS = ['otp', 'totp', '2fa', 'mfa', 'token', 'one-time', 'onetime', 'verification', 'auth', 'security code'];

// Payment-card detection. Note the ordering constraint: card classification
// must run BEFORE isLikelyTotp — cc-csc (maxLength 3-4) and cc-exp (4-5) are
// numeric and would otherwise be swallowed by the OTP length heuristics.
const CARD_AUTOCOMPLETE: Record<string, FieldKind> = {
    'cc-number': 'card_number',
    'cc-name': 'card_name',
    'cc-given-name': 'card_name',
    'cc-additional-name': 'card_name',
    'cc-family-name': 'card_name',
    'cc-exp': 'card_expiry',
    'cc-exp-month': 'card_expiry',
    'cc-exp-year': 'card_expiry',
    'cc-csc': 'card_cvv'
};

// Hints are matched against the de-symbolized haystack (spaces/_/- removed),
// so each entry below is written in compact form. Deliberately conservative:
// no bare 'pan', no 'security code'/'verification code' (those stay TOTP
// hints — card forms and login 2FA share those labels and changing them
// would regress TOTP detection).
const CARD_CVV_HINTS = ['cvv', 'cvv2', 'cvc', 'csc', 'cardverification'];
const CARD_EXPIRY_HINTS = ['expiry', 'expiration', 'expdate', 'expmonth', 'expyear', 'ccexp', 'validuntil', 'validthru'];
const CARD_NAME_HINTS = ['cardholder', 'nameoncard', 'cardname', 'ccname'];
const CARD_NUMBER_HINTS = ['cardnumber', 'cardnum', 'ccnumber', 'ccnum'];

function isVisibleInput(input: HTMLInputElement): boolean {
    if (input.disabled) return false;
    const style = window.getComputedStyle(input);
    if (style.display === 'none' || style.visibility === 'hidden') return false;
    return true;
}

function isLikelyTotp(input: HTMLInputElement): boolean {
    if (input.autocomplete === 'one-time-code') return true;

    const haystack = [
        input.name,
        input.id,
        input.placeholder,
        input.getAttribute('aria-label'),
        input.getAttribute('data-testid')
    ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();

    if (TOTP_HINTS.some((hint) => haystack.includes(hint))) return true;

    const maxLen = input.maxLength;
    const inputMode = (input.inputMode || '').toLowerCase();
    const pattern = (input.getAttribute('pattern') || '').toLowerCase();

    const looksNumeric =
        inputMode === 'numeric' ||
        pattern.includes('[0-9]') ||
        pattern.includes('\\d') ||
        input.type.toLowerCase() === 'number';

    if (looksNumeric && maxLen >= 4 && maxLen <= 10) return true;

    // Many OTP UIs use 6 separate inputs, one digit each.
    if (looksNumeric && maxLen === 1) return true;

    return false;
}

function classifyCardField(input: HTMLInputElement): FieldKind | null {
    const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
    if (autocomplete && CARD_AUTOCOMPLETE[autocomplete]) return CARD_AUTOCOMPLETE[autocomplete];

    const raw = [
        input.name,
        input.id,
        input.placeholder,
        input.getAttribute('aria-label'),
        input.getAttribute('data-testid')
    ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
    if (!raw) return null;
    const compact = raw.replace(/[\s_-]/g, '');

    if (CARD_CVV_HINTS.some((hint) => compact.includes(hint))) return 'card_cvv';
    if (CARD_EXPIRY_HINTS.some((hint) => compact.includes(hint))) return 'card_expiry';
    if (CARD_NAME_HINTS.some((hint) => compact.includes(hint))) return 'card_name';
    if (CARD_NUMBER_HINTS.some((hint) => compact.includes(hint))) return 'card_number';
    return null;
}

function classifyField(input: HTMLInputElement): FieldKind {
    const type = input.type.toLowerCase();
    if (type === 'password') return 'password';
    if (type === 'email') return 'email';
    // Card first: cc-csc/cc-exp shapes would be swallowed by isLikelyTotp.
    const cardKind = classifyCardField(input);
    if (cardKind) return cardKind;
    if (isLikelyTotp(input)) return 'totp';
    if (type === 'text' || type === 'search' || type === 'tel') {
        const name = (input.name || input.id || '').toLowerCase();
        if (USERNAME_HINTS.some((hint) => name.includes(hint))) return 'username';
        if (EMAIL_HINTS.some((hint) => name.includes(hint))) return 'email';
        return 'text';
    }
    if (type === 'number') {
        if (isLikelyTotp(input)) return 'totp';
    }
    return 'text';
}

function selectorFor(element: Element): string {
    if (element.id) {
        return `#${CSS.escape(element.id)}`;
    }
    const path: string[] = [];
    let current: Element | null = element;
    while (current && path.length < 4) {
        const tag = current.tagName.toLowerCase();
        const nth = Array.from(current.parentElement?.children ?? [])
            .filter((child) => child.tagName === current!.tagName)
            .indexOf(current) + 1;
        path.unshift(`${tag}:nth-of-type(${nth || 1})`);
        current = current.parentElement;
    }
    return path.join(' > ');
}

function scoreForm(fields: DetectedField[]): number {
    let score = 0;
    fields.forEach((field) => {
        if (field.type === 'password') score += 5;
        if (field.type === 'username' || field.type === 'email') score += 2;
        if (field.type === 'totp') score += 3;
        if (field.type === 'card_number') score += 5;
        if (field.type === 'card_name' || field.type === 'card_expiry') score += 2;
        if (field.type === 'card_cvv') score += 3;
    });
    return score;
}

function findVirtualFormRoot(input: HTMLInputElement): Element {
    const MAX_INPUTS = 10;
    const MIN_INPUTS = 2;
    const candidateTypes = new Set(['text', 'search', 'email', 'tel', 'password', 'number']);

    let node: Element | null = input.parentElement;
    for (let depth = 0; depth < 6 && node; depth++) {
        const inputs = Array.from(node.querySelectorAll('input'))
            .filter((el): el is HTMLInputElement => el instanceof HTMLInputElement)
            .filter((el) => candidateTypes.has(el.type.toLowerCase()))
            .filter(isVisibleInput);

        if (inputs.includes(input) && inputs.length >= MIN_INPUTS && inputs.length <= MAX_INPUTS) {
            return node;
        }

        node = node.parentElement;
    }

    return input.closest('main') ?? input.closest('section') ?? input.closest('div') ?? document.body;
}

function buildDetectedFormFromInputs(inputs: HTMLInputElement[], root: Document): DetectedForm | null {
    const fields: DetectedField[] = inputs
        .filter((input) => !!input.type)
        .map((input) => ({
            name: input.name || input.id || input.getAttribute('aria-label') || 'field',
            type: classifyField(input),
            selector: selectorFor(input)
        }));

    if (!fields.length) return null;
    const score = scoreForm(fields);
    if (score === 0) return null;
    return {
        action: root.location.href,
        method: 'POST',
        fields,
        score
    };
}

export function scanForms(root: Document = document): DetectedForm[] {
    const forms = Array.from(root.forms);
    const detected: DetectedForm[] = [];

    for (const form of forms) {
        const inputs = Array.from(form.querySelectorAll('input')) as HTMLInputElement[];
        const fields: DetectedField[] = inputs
            .filter((input) => !!input.type)
            .map((input) => ({
                name: input.name || input.id || 'field',
                type: classifyField(input),
                selector: selectorFor(input)
            }));

        if (!fields.length) continue;
        const score = scoreForm(fields);
        if (score === 0) continue;
        detected.push({
            action: form.action || root.location.href,
            method: (form.method || 'GET').toUpperCase(),
            fields,
            score
        });
    }

    // Some modern sites don't use <form>. Build "virtual forms" from grouped inputs.
    const allInputs = Array.from(root.querySelectorAll('input'))
        .filter((el): el is HTMLInputElement => el instanceof HTMLInputElement)
        .filter(isVisibleInput);

    const seenRoots = new Set<Element>();
    for (const input of allInputs) {
        if (input.form) continue;
        const kind = classifyField(input);
        // Card checkout pages have no password field: card_number seeds the
        // virtual-form grouping just like password/totp do for logins.
        if (kind !== 'password' && kind !== 'totp' && kind !== 'card_number') continue;

        const groupRoot = findVirtualFormRoot(input);
        if (seenRoots.has(groupRoot)) continue;
        seenRoots.add(groupRoot);

        const groupedInputs = Array.from(groupRoot.querySelectorAll('input'))
            .filter((el): el is HTMLInputElement => el instanceof HTMLInputElement)
            .filter(isVisibleInput);

        const virtual = buildDetectedFormFromInputs(groupedInputs, root);
        if (virtual) detected.push(virtual);
    }

    return detected;
}

export function observeForms(callback: (forms: DetectedForm[]) => void) {
    const emit = () => callback(scanForms());
    emit();
    const observer = new MutationObserver(() => emit());
    observer.observe(document.body, { childList: true, subtree: true });
    window.addEventListener('focus', emit);
    return () => {
        observer.disconnect();
        window.removeEventListener('focus', emit);
    };
}
