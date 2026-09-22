/**
 * formScanner 测试（jsdom）：字段分类（password/email/totp 启发式/username/email 提示词、
 * 信用卡四角色）、表单评分与过滤、virtual form 聚合、隐藏/禁用输入剔除、observeForms 生命周期。
 */
import { scanForms, observeForms, type DetectedForm } from './formScanner';

beforeAll(() => {
    // jsdom 若未内建 CSS.escape（selectorFor 依赖），提供最小实现
    const globalCss = (globalThis as any).CSS;
    if (typeof globalCss === 'undefined' || typeof globalCss.escape !== 'function') {
        (globalThis as any).CSS = {
            escape: (value: string) => value.replace(/[^a-zA-Z0-9_-]/g, (ch: string) => `\\${ch}`)
        };
    }
});

beforeEach(() => {
    document.body.innerHTML = '';
});

afterEach(() => {
    document.body.innerHTML = '';
});

function fieldTypes(form: DetectedForm): Record<string, string> {
    return Object.fromEntries(form.fields.map((field) => [field.name, field.type]));
}

describe('scanForms: real <form> elements', () => {
    it('classifies a login form and scores its fields', () => {
        document.body.innerHTML = `
            <form id="loginForm" action="/login" method="post">
                <input id="user" name="username" type="text">
                <input name="email" type="email">
                <input id="pw" name="password" type="password">
                <input name="otp" type="text" autocomplete="one-time-code">
            </form>
        `;

        const forms = scanForms();
        expect(forms).toHaveLength(1);

        const form = forms[0];
        expect(form.action).toBe('http://localhost/login');
        expect(form.method).toBe('POST');
        expect(fieldTypes(form)).toEqual({
            username: 'username',
            email: 'email',
            password: 'password',
            otp: 'totp'
        });
        // password 5 + username 2 + email 2 + totp 3
        expect(form.score).toBe(12);
    });

    it('prefers the element id for the selector when present', () => {
        document.body.innerHTML = `
            <form><input id="pw" name="password" type="password"></form>
        `;
        expect(scanForms()[0].fields[0].selector).toBe('#pw');
    });

    it('detects TOTP hints from name/id/placeholder/aria-label', () => {
        document.body.innerHTML = `
            <form>
                <input name="pw" type="password">
                <input id="code1" placeholder="Enter 2FA token" type="text">
                <input id="code2" aria-label="verification code" type="text">
            </form>
        `;
        const types = fieldTypes(scanForms()[0]);
        expect(types.code1).toBe('totp');
        expect(types.code2).toBe('totp');
    });

    it('detects numeric OTP shapes (type=number with maxLength 4..10) but not plain numbers', () => {
        document.body.innerHTML = `
            <form>
                <input name="pw" type="password">
                <input name="code" type="number" maxlength="6">
                <input name="qty" type="number">
            </form>
        `;
        const types = fieldTypes(scanForms()[0]);
        expect(types.code).toBe('totp');
        expect(types.qty).toBe('text');
    });

    it('classifies username/email from name hints on text inputs', () => {
        document.body.innerHTML = `
            <form>
                <input name="user" type="text">
                <input name="mail_addr" type="text">
                <input name="nickname" type="text">
            </form>
        `;
        const types = fieldTypes(scanForms()[0]);
        expect(types.user).toBe('username');
        expect(types.mail_addr).toBe('email');
        expect(types.nickname).toBe('text');
    });

    it('skips forms scoring zero (no password/username/email/totp)', () => {
        document.body.innerHTML = `
            <form><input name="q" type="text"><input name="age" type="number"></form>
        `;
        expect(scanForms()).toHaveLength(0);
    });

    it('scans each form independently', () => {
        document.body.innerHTML = `
            <form><input name="a_password" type="password"></form>
            <form><input name="b_password" type="password"></form>
        `;
        expect(scanForms()).toHaveLength(2);
    });
});

describe('scanForms: virtual forms (no <form> element)', () => {
    it('groups password + username inputs under a common ancestor', () => {
        document.body.innerHTML = `
            <div id="wrap">
                <input id="u" name="username" type="text">
                <input id="p" name="pw" type="password">
            </div>
        `;
        const forms = scanForms();
        expect(forms).toHaveLength(1);
        expect(forms[0].method).toBe('POST');
        expect(forms[0].action).toBe('http://localhost/');
        expect(forms[0].score).toBe(7);
        expect(fieldTypes(forms[0])).toEqual({ username: 'username', pw: 'password' });
    });

    it('aggregates six single-digit OTP inputs as one totp group', () => {
        document.body.innerHTML = `
            <div>
                ${[1, 2, 3, 4, 5, 6]
                    .map(
                        (n) =>
                            `<input name="digit${n}" type="tel" maxlength="1" pattern="[0-9]">`
                    )
                    .join('')}
            </div>
        `;
        const forms = scanForms();
        expect(forms).toHaveLength(1);
        expect(forms[0].fields).toHaveLength(6);
        expect(forms[0].score).toBe(18);
        expect(forms[0].fields.every((field) => field.type === 'totp')).toBe(true);
    });

    it('excludes hidden and disabled inputs from the group', () => {
        document.body.innerHTML = `
            <div id="wrap2">
                <input name="pw" type="password">
                <input name="user" type="text" style="display: none">
                <input name="nickname" type="text" disabled>
            </div>
        `;
        const forms = scanForms();
        expect(forms).toHaveLength(1);
        expect(forms[0].fields.map((field) => field.name)).toEqual(['pw']);
    });

    it('does not double-count inputs already inside a <form>', () => {
        document.body.innerHTML = `
            <form><input name="pw" type="password"><input name="username" type="text"></form>
        `;
        // 真实 form 扫描出 1 个；form 内输入不进入 virtual 聚合
        expect(scanForms()).toHaveLength(1);
    });
});

describe('scanForms: payment-card fields', () => {
    it('classifies card fields via autocomplete tokens (authoritative)', () => {
        document.body.innerHTML = `
            <form>
                <input name="pay" autocomplete="cc-number" type="tel">
                <input name="who" autocomplete="cc-name" type="text">
                <input name="when" autocomplete="cc-exp" type="tel">
                <input name="secret" autocomplete="cc-csc" type="tel">
            </form>
        `;
        const forms = scanForms();
        expect(forms).toHaveLength(1);
        expect(fieldTypes(forms[0])).toEqual({
            pay: 'card_number',
            who: 'card_name',
            when: 'card_expiry',
            secret: 'card_cvv'
        });
        // card_number 5 + card_name 2 + card_expiry 2 + card_cvv 3
        expect(forms[0].score).toBe(12);
    });

    it('classifies card fields from de-symbolized name/id hints', () => {
        document.body.innerHTML = `
            <form>
                <input name="card-number" type="tel">
                <input name="cardHolderName" type="text">
                <input id="expiry-date" type="tel">
                <input name="inputCvv" type="tel">
            </form>
        `;
        const types = fieldTypes(scanForms()[0]);
        expect(types['card-number']).toBe('card_number');
        expect(types.cardHolderName).toBe('card_name');
        expect(types['expiry-date']).toBe('card_expiry');
        expect(types.inputCvv).toBe('card_cvv');
    });

    it('classifies card fields before the TOTP heuristics can claim them', () => {
        document.body.innerHTML = `
            <form>
                <input name="cc-csc" type="tel" maxlength="4" pattern="[0-9]*">
                <input name="cc-exp" type="tel" maxlength="5" inputmode="numeric">
                <input name="cardnumber" type="tel" maxlength="19">
            </form>
        `;
        const types = fieldTypes(scanForms()[0]);
        // cc-csc (3-4 numeric) and cc-exp (4-5 numeric) would otherwise match
        // the OTP length shape.
        expect(types['cc-csc']).toBe('card_cvv');
        expect(types['cc-exp']).toBe('card_expiry');
        expect(types.cardnumber).toBe('card_number');
    });

    it('keeps login 2FA labels as TOTP even though card forms share them', () => {
        document.body.innerHTML = `
            <form>
                <input name="pw" type="password">
                <input id="code2" aria-label="verification code" type="text">
                <input name="sc" placeholder="Security code" type="text">
            </form>
        `;
        const types = fieldTypes(scanForms()[0]);
        expect(types.code2).toBe('totp');
        expect(types.sc).toBe('totp');
    });

    it('groups formless card inputs into a virtual checkout form', () => {
        document.body.innerHTML = `
            <div id="checkout">
                <input name="cardnumber" type="tel" maxlength="19">
                <input name="cardholder" type="text">
                <input name="exp-date" type="tel">
                <input name="cvc" type="tel" maxlength="4">
            </div>
        `;
        const forms = scanForms();
        expect(forms).toHaveLength(1);
        expect(fieldTypes(forms[0])).toEqual({
            cardnumber: 'card_number',
            cardholder: 'card_name',
            'exp-date': 'card_expiry',
            cvc: 'card_cvv'
        });
        expect(forms[0].score).toBe(12);
    });

    it('does not miscarry ordinary text fields as card fields', () => {
        document.body.innerHTML = `
            <form>
                <input name="username" type="text">
                <input name="company" type="text">
                <input name="desc" type="text">
            </form>
        `;
        const types = fieldTypes(scanForms()[0]);
        expect(types.username).toBe('username');
        expect(types.company).toBe('text');
        expect(types.desc).toBe('text');
    });
});

describe('observeForms', () => {
    it('emits immediately, on DOM mutations and on focus, then stops after cleanup', async () => {
        const seen: DetectedForm[][] = [];
        const stop = observeForms((forms) => seen.push(forms));

        expect(seen).toHaveLength(1); // 初始同步 emit（当前为空表单）
        expect(seen[0]).toHaveLength(0);

        document.body.innerHTML = '<form><input name="pw" type="password"></form>';
        await new Promise((resolve) => setTimeout(resolve, 0));
        const afterMutation = seen.length;
        expect(afterMutation).toBeGreaterThan(1);
        expect(seen[afterMutation - 1]).toHaveLength(1);

        stop();
        const countAtStop = seen.length;

        document.body.innerHTML = '<form><input name="pw2" type="password"></form>';
        window.dispatchEvent(new Event('focus'));
        await new Promise((resolve) => setTimeout(resolve, 0));
        expect(seen.length).toBe(countAtStop);
    });
});
