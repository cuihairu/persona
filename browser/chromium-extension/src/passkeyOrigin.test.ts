/**
 * passkeyOrigin 纯函数测试：origin 绑定校验（伪造 origin 丢弃、非法输入拒绝、
 * 规范化后相等、端口差异视为不同源）。
 */
import { isTrustedPasskeyOrigin } from './passkeyOrigin';

describe('isTrustedPasskeyOrigin', () => {
    it('accepts an origin that matches the page origin', () => {
        expect(isTrustedPasskeyOrigin('https://bank.com', 'https://bank.com')).toBe(true);
    });

    it('rejects a foreign origin (the forged-origin attack)', () => {
        // A malicious page at attacker.com tries to drive passkey ops for bank.com.
        expect(isTrustedPasskeyOrigin('https://bank.com', 'https://attacker.com')).toBe(false);
    });

    it('rejects non-string input', () => {
        expect(isTrustedPasskeyOrigin(undefined, 'https://bank.com')).toBe(false);
        expect(isTrustedPasskeyOrigin(null, 'https://bank.com')).toBe(false);
        expect(isTrustedPasskeyOrigin(42, 'https://bank.com')).toBe(false);
    });

    it('rejects malformed URLs without throwing', () => {
        expect(isTrustedPasskeyOrigin('not a url', 'https://bank.com')).toBe(false);
        expect(isTrustedPasskeyOrigin('', 'https://bank.com')).toBe(false);
    });

    it('normalizes a trailing slash to the bare origin', () => {
        expect(isTrustedPasskeyOrigin('https://bank.com/', 'https://bank.com')).toBe(true);
    });

    it('treats a differing port as a different origin', () => {
        expect(isTrustedPasskeyOrigin('https://bank.com:8443', 'https://bank.com')).toBe(false);
    });

    it('is case-sensitive on scheme', () => {
        expect(isTrustedPasskeyOrigin('http://bank.com', 'https://bank.com')).toBe(false);
    });
});
