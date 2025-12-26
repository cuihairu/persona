const USERNAME_HINTS = ['user', 'login', 'identifier'];
const EMAIL_HINTS = ['email', 'mail'];
const TOTP_HINTS = ['otp', 'totp', '2fa', 'mfa', 'token', 'one-time', 'onetime', 'verification', 'auth', 'security code'];
function isLikelyTotp(input) {
    if (input.autocomplete === 'one-time-code')
        return true;
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
    if (TOTP_HINTS.some((hint) => haystack.includes(hint)))
        return true;
    const maxLen = input.maxLength;
    const inputMode = (input.inputMode || '').toLowerCase();
    const pattern = (input.getAttribute('pattern') || '').toLowerCase();
    const looksNumeric = inputMode === 'numeric' ||
        pattern.includes('[0-9]') ||
        pattern.includes('\\d') ||
        input.type.toLowerCase() === 'number';
    if (looksNumeric && maxLen >= 4 && maxLen <= 10)
        return true;
    // Many OTP UIs use 6 separate inputs, one digit each.
    if (looksNumeric && maxLen === 1)
        return true;
    return false;
}
function classifyField(input) {
    const type = input.type.toLowerCase();
    if (type === 'password')
        return 'password';
    if (type === 'email')
        return 'email';
    if (isLikelyTotp(input))
        return 'totp';
    if (type === 'text' || type === 'search' || type === 'tel') {
        const name = (input.name || input.id || '').toLowerCase();
        if (USERNAME_HINTS.some((hint) => name.includes(hint)))
            return 'username';
        if (EMAIL_HINTS.some((hint) => name.includes(hint)))
            return 'email';
        return 'text';
    }
    if (type === 'number') {
        if (isLikelyTotp(input))
            return 'totp';
    }
    return 'text';
}
function selectorFor(element) {
    if (element.id) {
        return `#${CSS.escape(element.id)}`;
    }
    const path = [];
    let current = element;
    while (current && path.length < 4) {
        const tag = current.tagName.toLowerCase();
        const nth = Array.from(current.parentElement?.children ?? [])
            .filter((child) => child.tagName === current.tagName)
            .indexOf(current) + 1;
        path.unshift(`${tag}:nth-of-type(${nth || 1})`);
        current = current.parentElement;
    }
    return path.join(' > ');
}
function scoreForm(fields) {
    let score = 0;
    fields.forEach((field) => {
        if (field.type === 'password')
            score += 5;
        if (field.type === 'username' || field.type === 'email')
            score += 2;
        if (field.type === 'totp')
            score += 3;
    });
    return score;
}
export function scanForms(root = document) {
    const forms = Array.from(root.forms);
    const detected = [];
    for (const form of forms) {
        const inputs = Array.from(form.querySelectorAll('input'));
        const fields = inputs
            .filter((input) => !!input.type)
            .map((input) => ({
            name: input.name || input.id || 'field',
            type: classifyField(input),
            selector: selectorFor(input)
        }));
        if (!fields.length)
            continue;
        const score = scoreForm(fields);
        if (score === 0)
            continue;
        detected.push({
            action: form.action || root.location.href,
            method: (form.method || 'GET').toUpperCase(),
            fields,
            score
        });
    }
    return detected;
}
export function observeForms(callback) {
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
//# sourceMappingURL=formScanner.js.map