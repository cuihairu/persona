/**
 * Generator mode: the popup offers 1Password's two generation modes as a
 * segmented control — Characters (length + charset switches) and Passphrase
 * (word count). The native `generate_password` protocol takes
 * `words` (3–10) which overrides length and the character sets, and a
 * character-set toggle must stay on outside words mode, so the request is
 * assembled here per mode. Pure logic — DOM wiring lives in popup.ts.
 */

export type GenMode = 'characters' | 'passphrase';

export function normalizeMode(value: string | null | undefined): GenMode {
    return value === 'passphrase' ? 'passphrase' : 'characters';
}

export const WORDS_MIN = 3;
export const WORDS_MAX = 10;
export const LENGTH_MIN = 8;
export const LENGTH_MAX = 128;

export interface GenOptions {
    length: number;
    words: number;
    includeLowercase: boolean;
    includeUppercase: boolean;
    includeDigits: boolean;
    includeSymbols: boolean;
    pronounceable: boolean;
}

export interface GenRequest {
    length: number;
    include_lowercase: boolean;
    include_uppercase: boolean;
    include_digits: boolean;
    include_symbols: boolean;
    pronounceable: boolean;
    /** native Diceware override; omitted in characters mode (wire shape) */
    words?: number;
}

function clamp(value: number, min: number, max: number): number {
    return Math.min(max, Math.max(min, value));
}

/**
 * Assemble the wire request for the selected mode. Passphrase mode clamps
 * the word count into the native 3–10 window and forces pronounceable off
 * (words override the character sets, so the flag is meaningless there);
 * characters mode drops the word count and clamps the length.
 */
export function buildGenRequest(mode: GenMode, opts: GenOptions): GenRequest {
    if (mode === 'passphrase') {
        return {
            length: clamp(opts.length, LENGTH_MIN, LENGTH_MAX),
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
            pronounceable: false,
            words: clamp(Math.floor(opts.words) || WORDS_MIN, WORDS_MIN, WORDS_MAX)
        };
    }
    return {
        length: clamp(Math.floor(opts.length) || 16, LENGTH_MIN, LENGTH_MAX),
        include_lowercase: opts.includeLowercase,
        include_uppercase: opts.includeUppercase,
        include_digits: opts.includeDigits,
        include_symbols: opts.includeSymbols,
        pronounceable: opts.pronounceable,
        words: undefined
    };
}
