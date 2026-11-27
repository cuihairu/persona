import { bandFor, estimatePasswordStrength } from './genStrength.js';

describe('estimatePasswordStrength', () => {
    it('scores empty input at zero', () => {
        const v = estimatePasswordStrength('');
        expect(v.score).toBe(0);
        expect(v.band).toBe('weak');
    });

    it('ranks all-repeated characters as weak regardless of length', () => {
        const v = estimatePasswordStrength('aaaaaaaaaaaaaaaa');
        expect(v.band).toBe('weak');
        expect(v.score).toBeLessThan(40);
    });

    it('ranks a long full-charset password as excellent', () => {
        const v = estimatePasswordStrength('u7Kp!xR2#vLm9@Qz');
        expect(v.band).toBe('excellent');
        expect(v.score).toBeGreaterThanOrEqual(85);
    });

    it('places a short lowercase password in weak or fair', () => {
        const v = estimatePasswordStrength('hello');
        expect(['weak', 'fair']).toContain(v.band);
    });

    it('rewards added charset variety at fixed length', () => {
        const low = estimatePasswordStrength('abcdefghijkl').score;
        const mixed = estimatePasswordStrength('aB3cD4eF5gHiJ').score;
        expect(mixed).toBeGreaterThan(low);
    });

    it('rewards length at fixed charset', () => {
        const short = estimatePasswordStrength('abcdefgh').score;
        const long = estimatePasswordStrength('abcdefghijklmnop').score;
        expect(long).toBeGreaterThan(short);
    });

    it('clamps into 0-100', () => {
        expect(estimatePasswordStrength('aB3!aB3!aB3!aB3!aB3!aB3!aB3!aB3!').score).toBeLessThanOrEqual(100);
        expect(estimatePasswordStrength('a').score).toBeGreaterThanOrEqual(0);
    });

    it('is deterministic', () => {
        expect(estimatePasswordStrength('Sample#123')).toEqual(estimatePasswordStrength('Sample#123'));
    });
});

describe('bandFor', () => {
    it('maps the four bands at their thresholds', () => {
        expect(bandFor(0)).toBe('weak');
        expect(bandFor(39)).toBe('weak');
        expect(bandFor(40)).toBe('fair');
        expect(bandFor(64)).toBe('fair');
        expect(bandFor(65)).toBe('strong');
        expect(bandFor(84)).toBe('strong');
        expect(bandFor(85)).toBe('excellent');
        expect(bandFor(100)).toBe('excellent');
    });
});
