/**
 * WebAuthn passkey origin binding.
 *
 * The passkey `origin` is page-supplied over postMessage. Without binding it, a
 * malicious page could present another site's origin (e.g. `https://bank.com`)
 * to both the in-page dialog and the native approval gate, and on user consent
 * drive passkey creation/signing for an origin it does not own.
 *
 * An origin is trusted only when it normalizes (`scheme://host[:port]`) to the
 * page's own origin. Malformed/non-string input is rejected.
 */
export function isTrustedPasskeyOrigin(origin: unknown, pageOrigin: string): boolean {
    if (typeof origin !== 'string') return false;
    try {
        return new URL(origin).origin === pageOrigin;
    } catch {
        return false;
    }
}
