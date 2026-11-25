/**
 * domainPolicy pure-function tests: each heuristic fires individually, policy overrides win, upsert deduplicates, remove is case-insensitive.
 */
import {
    evaluateDomain,
    upsertPolicy,
    removePolicy,
    type DomainPolicy
} from './domainPolicy';

function policyOf(host: string, trust: 'trusted' | 'blocked'): DomainPolicy {
    return { host, trust, updatedAt: 1 };
}

describe('evaluateDomain heuristics', () => {
    it('plain host is unknown with no reasons', () => {
        const assessment = evaluateDomain('github.com');
        expect(assessment.risk).toBe('unknown');
        expect(assessment.reasons).toEqual([]);
        expect(assessment.host).toBe('github.com');
        expect(assessment.policy).toBeUndefined();
    });

    it('normalizes host casing before evaluation', () => {
        expect(evaluateDomain('GitHub.COM').host).toBe('github.com');
    });

    it('flags punycode/IDN domains', () => {
        const assessment = evaluateDomain('xn--pypal-4ve.com');
        expect(assessment.risk).toBe('suspicious');
        expect(assessment.reasons).toContain('Punycode/IDN domain detected');
    });

    it('flags non-ASCII hosts', () => {
        // "а" here is a Cyrillic letter, visually indistinguishable from the Latin "a" — a classic same-origin spoofing trick
        const assessment = evaluateDomain('pаypal.com');
        expect(assessment.risk).toBe('suspicious');
        expect(assessment.reasons).toContain('Non-ASCII characters present');
    });

    it('flags mixed alphanumeric labels but not digit-only labels', () => {
        const flagged = evaluateDomain('s3.example.com');
        expect(flagged.reasons).toContain('Mixed alphanumeric label "s3"');

        const digitsOnly = evaluateDomain('123.example.com');
        expect(digitsOnly.risk).toBe('unknown');
    });

    it('flags double hyphens in labels', () => {
        const assessment = evaluateDomain('my--bank.com');
        expect(assessment.risk).toBe('suspicious');
        expect(assessment.reasons).toContain('Double hyphen in label "my--bank"');
    });

    it('flags unusually long labels (over 24 chars)', () => {
        const longLabel = 'a'.repeat(25);
        const assessment = evaluateDomain(`${longLabel}.com`);
        expect(assessment.reasons).toContain(`Unusually long label (25 chars)`);
    });

    it('flags high-risk TLDs after normalization', () => {
        const assessment = evaluateDomain('SAFE.ZIP');
        expect(assessment.risk).toBe('suspicious');
        expect(assessment.reasons).toContain('High-risk TLD .zip');
    });

    it('accumulates multiple heuristics into reasons', () => {
        // xn-- prefix + double hyphen + mixed alphanumeric + risky TLD, all hit at once
        const assessment = evaluateDomain('xn--a--b1.zip');
        expect(assessment.risk).toBe('suspicious');
        expect(assessment.reasons.length).toBeGreaterThanOrEqual(3);
    });
});

describe('evaluateDomain policy override', () => {
    it('a trusted policy overrides suspicious heuristics', () => {
        const policies = [policyOf('foo.zip', 'trusted')];
        const assessment = evaluateDomain('foo.zip', policies);
        expect(assessment.risk).toBe('trusted');
        expect(assessment.reasons).toEqual(['User trusted domain']);
        expect(assessment.policy).toBe(policies[0]);
    });

    it('a blocked policy wins over heuristics', () => {
        const policies = [policyOf('github.com', 'blocked')];
        const assessment = evaluateDomain('github.com', policies);
        expect(assessment.risk).toBe('blocked');
        expect(assessment.reasons).toEqual(['User blocked domain']);
    });

    it('policy lookup is case-insensitive for the queried host', () => {
        // stored policies are always lowercased by upsertPolicy; the query side may use any case
        const policies = [policyOf('foo.zip', 'trusted')];
        expect(evaluateDomain('foo.zip', policies).risk).toBe('trusted');
        expect(evaluateDomain('FOO.ZIP', policies).risk).toBe('trusted');
    });
});

describe('upsertPolicy / removePolicy', () => {
    it('appends a new policy with lowercased host and fresh updatedAt', () => {
        const next = upsertPolicy([], { host: 'Example.COM', trust: 'trusted', updatedAt: 1 });
        expect(next).toHaveLength(1);
        expect(next[0].host).toBe('example.com');
        expect(next[0].updatedAt).toBeGreaterThan(1);
    });

    it('replaces the entry for the same host ignoring case', () => {
        const first = upsertPolicy([], policyOf('a.com', 'trusted'));
        const second = upsertPolicy(first, { host: 'A.com', trust: 'blocked', updatedAt: 2 });
        expect(second).toHaveLength(1);
        expect(second[0].trust).toBe('blocked');
        expect(second[0].host).toBe('a.com');
    });

    it('keeps other policies when upserting', () => {
        const withA = upsertPolicy([], policyOf('a.com', 'trusted'));
        const withB = upsertPolicy(withA, policyOf('b.com', 'blocked'));
        expect(withB.map((p) => p.host)).toEqual(['a.com', 'b.com']);
    });

    it('removes only the matching host ignoring case', () => {
        const policies = [policyOf('a.com', 'trusted'), policyOf('b.com', 'blocked')];
        const next = removePolicy(policies, 'A.com');
        expect(next.map((p) => p.host)).toEqual(['b.com']);
    });
});
