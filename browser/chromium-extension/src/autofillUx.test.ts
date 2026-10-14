/**
 * autofillUx 测试：TOTP 临期判定/等待时长/通知文案，以及候选选择的
 * 单一命中、默认记忆、歧义标记。
 */
import {
    TOTP_STALE_THRESHOLD_SECONDS,
    contextHintLine,
    freshTotpWaitMs,
    pickSuggestion,
    shouldWaitForFreshTotp,
    suggestionMetaLine,
    totpCopiedNotice,
    totpFilledNotice,
    type AutofillCandidate
} from './autofillUx';

const cand = (
    item_id: string,
    match_strength: number,
    credential_type = 'totp'
): AutofillCandidate => ({ item_id, match_strength, credential_type });

describe('shouldWaitForFreshTotp', () => {
    it('waits only inside the stale window', () => {
        expect(shouldWaitForFreshTotp(0)).toBe(true);
        expect(shouldWaitForFreshTotp(TOTP_STALE_THRESHOLD_SECONDS)).toBe(true);
        expect(shouldWaitForFreshTotp(TOTP_STALE_THRESHOLD_SECONDS + 1)).toBe(false);
        expect(shouldWaitForFreshTotp(15)).toBe(false);
    });

    it('ignores garbage and negatives', () => {
        expect(shouldWaitForFreshTotp(undefined)).toBe(false);
        expect(shouldWaitForFreshTotp(Number.NaN)).toBe(false);
        expect(shouldWaitForFreshTotp(-1)).toBe(false);
    });
});

describe('freshTotpWaitMs', () => {
    it('waits out the window plus one second of slack', () => {
        expect(freshTotpWaitMs(0)).toBe(1000);
        expect(freshTotpWaitMs(3)).toBe(4000);
        expect(freshTotpWaitMs(-5)).toBe(1000);
    });
});

describe('notices', () => {
    it('carries the remaining window when known', () => {
        expect(totpFilledNotice(12)).toBe('2FA code filled (expires in 12s)');
        expect(totpCopiedNotice(12)).toBe('2FA code copied (expires in 12s)');
        expect(totpCopiedNotice(12, true)).toBe('2FA code copied (fallback) (expires in 12s)');
    });

    it('degrades to the plain notice without remaining seconds', () => {
        expect(totpFilledNotice(undefined)).toBe('2FA code filled');
        expect(totpCopiedNotice(undefined)).toBe('2FA code copied');
        expect(totpCopiedNotice(undefined, true)).toBe('2FA code copied (fallback)');
    });
});

describe('pickSuggestion', () => {
    const items = [
        cand('weak', 40),
        cand('strong', 95),
        cand('login-strong', 99, 'password')
    ];

    it('picks the unique match above the strength floor', () => {
        const { picked, ambiguous } = pickSuggestion(items, 'totp', 90, null);
        expect(picked?.item_id).toBe('strong');
        expect(ambiguous).toBe(false);
    });

    it('filters out other modes and weak matches', () => {
        const { picked, ambiguous } = pickSuggestion(items, 'totp', 100, null);
        expect(picked).toBeNull();
        expect(ambiguous).toBe(false);
        const login = pickSuggestion(items, 'password', 90, null);
        expect(login.picked?.item_id).toBe('login-strong');
    });

    it('returns ambiguous when several tie and no default is remembered', () => {
        const two = [cand('a', 90), cand('b', 91)];
        const { picked, ambiguous } = pickSuggestion(two, 'totp', 90, null);
        expect(picked).toBeNull();
        expect(ambiguous).toBe(true);
    });

    it('prefers the remembered default among candidates', () => {
        const two = [cand('a', 90), cand('b', 91)];
        const { picked, ambiguous } = pickSuggestion(two, 'totp', 90, 'a');
        expect(picked?.item_id).toBe('a');
        expect(ambiguous).toBe(false);
    });

    it('flags ambiguity when the remembered default is gone', () => {
        const two = [cand('a', 90), cand('b', 91)];
        const { picked, ambiguous } = pickSuggestion(two, 'totp', 90, 'missing');
        expect(picked).toBeNull();
        expect(ambiguous).toBe(true);
    });

    it('treats missing credential_type as password', () => {
        const bare: AutofillCandidate[] = [{ item_id: 'x', match_strength: 95 }];
        expect(pickSuggestion(bare, 'password', 90, null).picked?.item_id).toBe('x');
        expect(pickSuggestion(bare, 'totp', 90, null).picked).toBeNull();
    });
});

describe('suggestionMetaLine (stage 4 identity labels)', () => {
    it('renders kind, match and username hint as before', () => {
        expect(
            suggestionMetaLine({
                credential_type: 'password',
                match_strength: 100,
                username_hint: 'a@b.c'
            })
        ).toBe('PASSWORD • match 100 • a@b.c');
    });

    it('appends the owning identity when the bridge provides one', () => {
        expect(
            suggestionMetaLine({
                credential_type: 'totp',
                match_strength: 90,
                username_hint: 'a@b.c',
                identity: 'Work'
            })
        ).toBe('TOTP • match 90 • a@b.c • Work');
    });

    it('keeps the legacy shape when identity is absent', () => {
        expect(suggestionMetaLine({ match_strength: 80 })).toBe('PASSWORD • match 80');
        expect(suggestionMetaLine({ match_strength: 80, identity: null })).toBe(
            'PASSWORD • match 80'
        );
    });

    it('spells card kinds with a space', () => {
        expect(
            suggestionMetaLine({ credential_type: 'bank_card', match_strength: 100, identity: 'Work' })
        ).toBe('BANK CARD • match 100 • Work');
    });
});

describe('contextHintLine (stage 4 context field)', () => {
    it('returns null when the bridge sent no context suggestion', () => {
        expect(contextHintLine(undefined)).toBeNull();
        expect(contextHintLine(null)).toBeNull();
    });

    it('formats identity and score', () => {
        expect(contextHintLine({ identity: 'Work', score: 1, reason: 'repo x' })).toBe(
            'Context suggests Work (score 1.00)'
        );
    });

    it('tolerates a missing or non-numeric score', () => {
        expect(contextHintLine({ identity: 'Work' })).toBe('Context suggests Work (score ?)');
        expect(contextHintLine({ identity: 'OpenSource', score: NaN, reason: '' })).toBe(
            'Context suggests OpenSource (score ?)'
        );
    });
});
