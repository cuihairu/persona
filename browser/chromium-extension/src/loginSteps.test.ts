/**
 * loginSteps 测试：多步登录决策（纯函数）。锁定三条安全边界——载入时只填
 * 「自报身份」的字段（autocomplete / login-user-account 命名）、已有值不覆盖、
 * 候选不可唯一解析时不动手。
 */
import { planLoginStep, type LoginStepInput } from './loginSteps';

function field(
    overrides: Partial<{ kind: 'username' | 'email' | 'text' | 'password' | 'none'; autocomplete: string; hasValue: boolean; isFocused: boolean }> = {}
) {
    return {
        kind: 'email' as const,
        autocomplete: '',
        hasValue: false,
        isFocused: false,
        ...overrides
    };
}

function input(overrides: Partial<LoginStepInput> = {}): LoginStepInput {
    return {
        trigger: 'load',
        hasPasswordField: false,
        identityField: field(),
        hasResolvableSuggestion: true,
        ...overrides
    };
}

describe('planLoginStep — password present', () => {
    it('fills credentials on load when a password field is in view', () => {
        expect(planLoginStep(input({ hasPasswordField: true }))).toBe('credentials');
    });

    it('fills credentials on focus too, even without an identity field', () => {
        expect(
            planLoginStep(input({ trigger: 'focus', hasPasswordField: true, identityField: null }))
        ).toBe('credentials');
    });

    it('waits when nothing is resolvable', () => {
        expect(planLoginStep(input({ hasPasswordField: true, hasResolvableSuggestion: false }))).toBe('wait');
    });
});

describe('planLoginStep — username-only step', () => {
    it('fills a login-named field on load (scanner username bucket)', () => {
        expect(planLoginStep(input({ identityField: field({ kind: 'username' }) }))).toBe('username');
    });

    it('fills an explicit autocomplete=username / email field on load', () => {
        expect(
            planLoginStep(input({ identityField: field({ kind: 'text', autocomplete: 'username' }) }))
        ).toBe('username');
        expect(
            planLoginStep(input({ identityField: field({ kind: 'email', autocomplete: 'email' }) }))
        ).toBe('username');
    });

    it('refuses a bare email box on load (newsletter signup ambiguity)', () => {
        expect(planLoginStep(input({ identityField: field({ kind: 'email' }) }))).toBe('wait');
    });

    it('refuses bare text fields on load (newsletter/search boxes)', () => {
        expect(planLoginStep(input({ identityField: field({ kind: 'text' }) }))).toBe('wait');
    });

    it('fills a bare email/text field once the user focuses it', () => {
        expect(
            planLoginStep(
                input({
                    trigger: 'focus',
                    identityField: field({ kind: 'email', isFocused: true })
                })
            )
        ).toBe('username');
        expect(
            planLoginStep(
                input({ trigger: 'focus', identityField: field({ kind: 'text', isFocused: true }) })
            )
        ).toBe('username');
    });

    it('waits on focus when the identity field is not the focused one', () => {
        expect(
            planLoginStep(input({ trigger: 'focus', identityField: field({ kind: 'email', isFocused: false }) }))
        ).toBe('wait');
    });

    it('never overwrites a field that already has a value', () => {
        for (const trigger of ['load', 'focus'] as const) {
            expect(
                planLoginStep(
                    input({ trigger, identityField: field({ kind: 'username', hasValue: true, isFocused: true }) })
                )
            ).toBe('wait');
        }
    });

    it('waits without an identity field', () => {
        expect(planLoginStep(input({ identityField: null }))).toBe('wait');
    });

    it('waits when the only field is a password (nothing to fill in step 1)', () => {
        expect(
            planLoginStep(input({ identityField: field({ kind: 'password', isFocused: true }) }))
        ).toBe('wait');
    });

    it('waits when the suggestion is ambiguous (no unique item for this origin)', () => {
        expect(
            planLoginStep(
                input({
                    hasResolvableSuggestion: false,
                    identityField: field({ kind: 'username' })
                })
            )
        ).toBe('wait');
    });
});