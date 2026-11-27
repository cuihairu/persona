// Local strength estimate for generated passwords. Deliberately a cheap
// heuristic (charset pool × length × repetition penalty), not a real entropy
// attack model — it only ever ranks generator output to give the operator a
// visual signal; nothing is stored or reported anywhere.

export type StrengthBand = 'weak' | 'fair' | 'strong' | 'excellent';

export interface StrengthVerdict {
    /** 0-100, monotonically comparable. */
    score: number;
    band: StrengthBand;
}

const CHARSET_BITS: Array<[RegExp, number]> = [
    [/[a-z]/, 4.7], // ~log2(26)
    [/[A-Z]/, 4.7],
    [/[0-9]/, 3.32], // ~log2(10)
    [/[^a-zA-Z0-9]/, 5.04] // ~log2(33) common ASCII symbols
];

export function estimatePasswordStrength(password: string): StrengthVerdict {
    if (!password) return { score: 0, band: 'weak' };

    let bitsPerChar = 0;
    for (const [pattern, bits] of CHARSET_BITS) {
        if (pattern.test(password)) bitsPerChar += bits;
    }

    const length = password.length;
    const uniqueRatio = new Set(password).size / length;
    // repeated content carries little extra entropy; the log-ish curve keeps
    // fully-repeated strings near zero while barely touching diverse ones
    const diversity = 0.35 + 0.65 * Math.pow(uniqueRatio, 0.6);

    const bits = length * bitsPerChar * diversity;
    const score = Math.max(0, Math.min(100, Math.round((bits / 130) * 100)));

    return { score, band: bandFor(score) };
}

export function bandFor(score: number): StrengthBand {
    if (score < 40) return 'weak';
    if (score < 65) return 'fair';
    if (score < 85) return 'strong';
    return 'excellent';
}
