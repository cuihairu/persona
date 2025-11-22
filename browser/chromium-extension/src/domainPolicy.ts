export type TrustLevel = 'trusted' | 'blocked';
export type RiskLevel = TrustLevel | 'suspicious' | 'unknown';

export interface DomainPolicy {
    host: string;
    trust: TrustLevel;
    note?: string;
    updatedAt: number;
}

export interface DomainAssessment {
    host: string;
    risk: RiskLevel;
    reasons: string[];
    policy?: DomainPolicy;
}

const SUSPICIOUS_TLDS = new Set([
    'zip',
    'mov',
    'xyz',
    'top',
    'gq',
    'work',
    'click',
    'country',
    'support'
]);

function collectHeuristics(host: string): string[] {
    const reasons: string[] = [];
    if (host.includes('xn--')) {
        reasons.push('Punycode/IDN domain detected');
    }
    if (/[^\u0000-\u007f]/.test(host)) {
        reasons.push('Non-ASCII characters present');
    }

    const labels = host.split('.').filter(Boolean);
    for (const label of labels) {
        if (/\d/.test(label) && /[a-z]/i.test(label)) {
            reasons.push(`Mixed alphanumeric label "${label}"`);
        }
        if (label.includes('--')) {
            reasons.push(`Double hyphen in label "${label}"`);
        }
        if (label.length > 24) {
            reasons.push(`Unusually long label (${label.length} chars)`);
        }
    }

    const tld = labels.length ? labels[labels.length - 1] : undefined;
    if (tld && SUSPICIOUS_TLDS.has(tld.toLowerCase())) {
        reasons.push(`High-risk TLD .${tld}`);
    }

    return reasons;
}

export function evaluateDomain(host: string, policies: DomainPolicy[] = []): DomainAssessment {
    const normalized = host.toLowerCase();
    const policy = policies.find((p) => p.host === normalized);
    if (policy) {
        return {
            host: normalized,
            policy,
            risk: policy.trust,
            reasons: [policy.trust === 'trusted' ? 'User trusted domain' : 'User blocked domain']
        };
    }

    const reasons = collectHeuristics(normalized);
    return {
        host: normalized,
        risk: reasons.length ? 'suspicious' : 'unknown',
        reasons
    };
}

export function upsertPolicy(policies: DomainPolicy[], policy: DomainPolicy): DomainPolicy[] {
    const normalized = policy.host.toLowerCase();
    const filtered = policies.filter((p) => p.host !== normalized);
    return [...filtered, { ...policy, host: normalized, updatedAt: Date.now() }];
}

export function removePolicy(policies: DomainPolicy[], host: string): DomainPolicy[] {
    const normalized = host.toLowerCase();
    return policies.filter((p) => p.host !== normalized);
}
