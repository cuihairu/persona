use std::sync::OnceLock;

use crate::{PersonaError, Result};
use rand::{rngs::ThreadRng, seq::SliceRandom, RngExt};

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

const LOWER_VOWELS: &str = "aeiou";
const UPPER_VOWELS: &str = "AEIOU";
const LOWER_CONSONANTS: &str = "bcdfghjklmnpqrstvwxyz";
const UPPER_CONSONANTS: &str = "BCDFGHJKLMNPQRSTVWXYZ";

/// Options used when generating passwords.
#[derive(Debug, Clone)]
pub struct PasswordGeneratorOptions {
    /// Desired password length.
    pub length: usize,
    /// Include lowercase letters.
    pub include_lowercase: bool,
    /// Include uppercase letters.
    pub include_uppercase: bool,
    /// Include numeric characters.
    pub include_numbers: bool,
    /// Include symbol characters.
    pub include_symbols: bool,
    /// Generate pronounceable passwords (alternating consonants/vowels).
    pub pronounceable: bool,
    /// Generate a word-based passphrase (Diceware-style): `Some(n)` picks `n`
    /// words from the embedded EFF large wordlist and joins them with `-`.
    /// Ignores `length` and the character sets; conflicts with `pronounceable`.
    pub words: Option<usize>,
}

impl Default for PasswordGeneratorOptions {
    fn default() -> Self {
        Self {
            length: 16,
            include_lowercase: true,
            include_uppercase: true,
            include_numbers: true,
            include_symbols: true,
            pronounceable: false,
            words: None,
        }
    }
}

/// Password generation helper shared by CLI/Desktop/Server.
pub struct PasswordGenerator;

impl PasswordGenerator {
    /// Generate a password for the provided configuration.
    pub fn generate(options: &PasswordGeneratorOptions) -> Result<String> {
        Self::validate_options(options)?;

        if let Some(word_count) = options.words {
            return Ok(Self::generate_words(word_count));
        }

        if options.pronounceable {
            Self::generate_pronounceable(options)
        } else {
            Self::generate_random(options)
        }
    }

    fn validate_options(options: &PasswordGeneratorOptions) -> Result<()> {
        if let Some(word_count) = options.words {
            if options.pronounceable {
                return Err(PersonaError::InvalidInput(
                    "Words mode cannot be combined with pronounceable".to_string(),
                )
                .into());
            }
            if !(3..=10).contains(&word_count) {
                return Err(PersonaError::InvalidInput(
                    "Passphrase word count must be between 3 and 10".to_string(),
                )
                .into());
            }
            // Word passphrases derive their shape from the word count alone:
            // the length minimum and the character-set selection do not apply.
            return Ok(());
        }

        if options.length < 4 {
            return Err(PersonaError::InvalidInput(
                "Password length must be at least 4 characters".to_string(),
            )
            .into());
        }

        if options.pronounceable && !(options.include_lowercase || options.include_uppercase) {
            return Err(PersonaError::InvalidInput(
                "Pronounceable passwords require lowercase and/or uppercase letters".to_string(),
            )
            .into());
        }

        if !options.pronounceable
            && !(options.include_lowercase
                || options.include_uppercase
                || options.include_numbers
                || options.include_symbols)
        {
            return Err(PersonaError::InvalidInput(
                "At least one character set must be enabled".to_string(),
            )
            .into());
        }

        Ok(())
    }

    fn generate_random(options: &PasswordGeneratorOptions) -> Result<String> {
        let mut pools: Vec<&'static str> = Vec::new();
        if options.include_lowercase {
            pools.push(LOWERCASE);
        }
        if options.include_uppercase {
            pools.push(UPPERCASE);
        }
        if options.include_numbers {
            pools.push(DIGITS);
        }
        if options.include_symbols {
            pools.push(SYMBOLS);
        }

        if pools.is_empty() {
            return Err(PersonaError::InvalidInput(
                "At least one character set must be enabled".to_string(),
            )
            .into());
        }

        // Note: `options.length < pools.len()` is impossible here — length is
        // validated to be >= 4 above and at most 4 pools can be selected.

        let mut rng = rand::rng();

        // Build a combined pool for general selection
        let combined: Vec<char> = pools.iter().flat_map(|set| set.chars()).collect();
        let mut password_chars = Vec::with_capacity(options.length);

        // Guarantee at least one character from each selected set
        for set in &pools {
            password_chars.push(Self::choose_random_char(set, &mut rng));
        }

        while password_chars.len() < options.length {
            let ch = combined[rng.random_range(0..combined.len())];
            password_chars.push(ch);
        }

        password_chars.shuffle(&mut rng);
        Ok(password_chars.into_iter().collect())
    }

    fn generate_pronounceable(options: &PasswordGeneratorOptions) -> Result<String> {
        let mut consonants = String::new();
        if options.include_lowercase {
            consonants.push_str(LOWER_CONSONANTS);
        }
        if options.include_uppercase {
            consonants.push_str(UPPER_CONSONANTS);
        }

        let mut vowels = String::new();
        if options.include_lowercase {
            vowels.push_str(LOWER_VOWELS);
        }
        if options.include_uppercase {
            vowels.push_str(UPPER_VOWELS);
        }

        if consonants.is_empty() && vowels.is_empty() {
            return Err(PersonaError::InvalidInput(
                "Pronounceable passwords require at least one letter set".to_string(),
            )
            .into());
        }

        let mut rng = rand::rng();
        let mut password_chars = Vec::with_capacity(options.length);
        let mut use_consonant = true;

        for _ in 0..options.length {
            let pool = if use_consonant && !consonants.is_empty() {
                consonants.as_str()
            } else if !vowels.is_empty() {
                vowels.as_str()
            } else {
                consonants.as_str()
            };

            password_chars.push(Self::choose_random_char(pool, &mut rng));
            use_consonant = !use_consonant;
        }

        // Inject required digits/symbols by replacing random positions if enabled.
        if options.include_numbers {
            Self::inject_character_from_set(&mut password_chars, DIGITS, &mut rng);
        }
        if options.include_symbols {
            Self::inject_character_from_set(&mut password_chars, SYMBOLS, &mut rng);
        }

        Ok(password_chars.into_iter().collect())
    }

    /// The embedded EFF large wordlist (7772 unique lowercase words; `#`
    /// comment lines and blank lines skipped), loaded once per process.
    fn wordlist() -> &'static [&'static str] {
        static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
        WORDS
            .get_or_init(|| {
                include_str!("eff_large_wordlist.txt")
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .collect()
            })
            .as_slice()
    }

    /// Diceware-style passphrase: `word_count` words drawn uniformly from the
    /// embedded wordlist, joined with `-`. Range and combination rules are
    /// enforced by `validate_options` before this is called.
    fn generate_words(word_count: usize) -> String {
        let words = Self::wordlist();
        let mut rng = rand::rng();
        let mut chosen = Vec::with_capacity(word_count);
        for _ in 0..word_count {
            chosen.push(words[rng.random_range(0..words.len())]);
        }
        chosen.join("-")
    }

    fn choose_random_char(set: &str, rng: &mut ThreadRng) -> char {
        let bytes = set.as_bytes();
        let idx = rng.random_range(0..bytes.len());
        bytes[idx] as char
    }

    fn inject_character_from_set(chars: &mut [char], set: &str, rng: &mut ThreadRng) {
        if chars.is_empty() {
            return;
        }

        let idx = rng.random_range(0..chars.len());
        chars[idx] = Self::choose_random_char(set, rng);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_random_password_with_symbols() {
        let options = PasswordGeneratorOptions {
            length: 24,
            include_lowercase: true,
            include_uppercase: true,
            include_numbers: true,
            include_symbols: true,
            pronounceable: false,
            words: None,
        };

        let password = PasswordGenerator::generate(&options).unwrap();
        assert_eq!(password.len(), 24);
        assert!(password.chars().any(|c| LOWERCASE.contains(c)));
        assert!(password.chars().any(|c| UPPERCASE.contains(c)));
        assert!(password.chars().any(|c| DIGITS.contains(c)));
        assert!(password.chars().any(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn generates_pronounceable_password() {
        let options = PasswordGeneratorOptions {
            length: 12,
            include_lowercase: true,
            include_uppercase: false,
            include_numbers: false,
            include_symbols: false,
            pronounceable: true,
            words: None,
        };

        let password = PasswordGenerator::generate(&options).unwrap();
        assert_eq!(password.len(), 12);
        assert!(password.chars().all(|c| LOWERCASE.contains(c)));
    }

    #[test]
    fn errors_when_no_sets_selected() {
        let options = PasswordGeneratorOptions {
            length: 16,
            include_lowercase: false,
            include_uppercase: false,
            include_numbers: false,
            include_symbols: false,
            pronounceable: false,
            words: None,
        };

        let err = PasswordGenerator::generate(&options).unwrap_err();
        assert!(err
            .to_string()
            .contains("At least one character set must be enabled"));
    }

    #[test]
    fn rejects_short_length() {
        let options = PasswordGeneratorOptions {
            length: 3,
            include_lowercase: true,
            ..PasswordGeneratorOptions::default()
        };
        let err = PasswordGenerator::generate(&options).unwrap_err();
        assert!(err
            .to_string()
            .contains("Password length must be at least 4 characters"));
    }

    #[test]
    fn pronounceable_requires_letters() {
        let options = PasswordGeneratorOptions {
            length: 16,
            include_lowercase: false,
            include_uppercase: false,
            include_numbers: true,
            include_symbols: true,
            pronounceable: true,
            words: None,
        };
        let err = PasswordGenerator::generate(&options).unwrap_err();
        assert!(err
            .to_string()
            .contains("Pronounceable passwords require lowercase and/or uppercase"));
    }

    #[test]
    fn single_charset_password_uses_only_that_set() {
        let options = PasswordGeneratorOptions {
            length: 32,
            include_lowercase: false,
            include_uppercase: false,
            include_numbers: true,
            include_symbols: false,
            pronounceable: false,
            words: None,
        };
        let password = PasswordGenerator::generate(&options).unwrap();
        assert_eq!(password.len(), 32);
        assert!(password.chars().all(|c| DIGITS.contains(c)));
    }

    #[test]
    fn pronounceable_password_supports_uppercase() {
        let options = PasswordGeneratorOptions {
            length: 20,
            include_lowercase: false,
            include_uppercase: true,
            include_numbers: false,
            include_symbols: false,
            pronounceable: true,
            words: None,
        };
        let password = PasswordGenerator::generate(&options).unwrap();
        assert_eq!(password.len(), 20);
        assert!(password.chars().all(|c| UPPERCASE.contains(c)));
    }

    #[test]
    fn pronounceable_password_mixed_case() {
        let options = PasswordGeneratorOptions {
            length: 24,
            include_lowercase: true,
            include_uppercase: true,
            include_numbers: false,
            include_symbols: false,
            pronounceable: true,
            words: None,
        };
        let password = PasswordGenerator::generate(&options).unwrap();
        assert_eq!(password.len(), 24);
        assert!(password
            .chars()
            .all(|c| LOWERCASE.contains(c) || UPPERCASE.contains(c)));
    }

    #[test]
    fn pronounceable_password_injects_digits_and_symbols() {
        // Injection replaces one random position per enabled set. The symbol
        // pass runs last, so every password carries a symbol; the digit pass
        // can be overwritten when both land on the same position, so digits
        // are only required to appear across several runs.
        let mut saw_digit = false;
        for _ in 0..25 {
            let options = PasswordGeneratorOptions {
                length: 16,
                include_lowercase: true,
                include_uppercase: false,
                include_numbers: true,
                include_symbols: true,
                pronounceable: true,
                words: None,
            };
            let password = PasswordGenerator::generate(&options).unwrap();
            assert_eq!(password.len(), 16);
            assert!(
                password.chars().all(|c| {
                    LOWERCASE.contains(c) || DIGITS.contains(c) || SYMBOLS.contains(c)
                }),
                "unexpected character in {password}"
            );
            assert!(
                password.chars().any(|c| SYMBOLS.contains(c)),
                "symbol injection failed for {password}"
            );
            saw_digit |= password.chars().any(|c| DIGITS.contains(c));
        }
        assert!(saw_digit, "digit never appeared across runs");
    }

    #[test]
    fn pronounceable_password_injection_is_per_set_reliable() {
        // With only one injected set there is nothing to overwrite it, so
        // every generated password must contain that set.
        for include_numbers in [true, false] {
            let options = PasswordGeneratorOptions {
                length: 20,
                include_lowercase: true,
                include_uppercase: false,
                include_numbers,
                include_symbols: !include_numbers,
                pronounceable: true,
                words: None,
            };
            let password = PasswordGenerator::generate(&options).unwrap();
            assert_eq!(password.len(), 20);
            if include_numbers {
                assert!(password.chars().any(|c| DIGITS.contains(c)));
                assert!(password
                    .chars()
                    .all(|c| LOWERCASE.contains(c) || DIGITS.contains(c)));
            } else {
                assert!(password.chars().any(|c| SYMBOLS.contains(c)));
                assert!(password
                    .chars()
                    .all(|c| LOWERCASE.contains(c) || SYMBOLS.contains(c)));
            }
        }
    }

    #[test]
    fn default_options_are_documented_values() {
        let options = PasswordGeneratorOptions::default();
        assert_eq!(options.length, 16);
        assert!(options.include_lowercase);
        assert!(options.include_uppercase);
        assert!(options.include_numbers);
        assert!(options.include_symbols);
        assert!(!options.pronounceable);

        // Default options generate a 16-char password using all four sets.
        let password = PasswordGenerator::generate(&options).unwrap();
        assert_eq!(password.len(), 16);
        assert!(password.chars().all(|c| {
            LOWERCASE.contains(c)
                || UPPERCASE.contains(c)
                || DIGITS.contains(c)
                || SYMBOLS.contains(c)
        }));
    }

    #[test]
    fn generators_reject_empty_character_sets_directly() {
        // generate() validates up front, so the duplicated guards inside the
        // private generators are exercised directly here.
        let no_sets = PasswordGeneratorOptions {
            length: 12,
            include_lowercase: false,
            include_uppercase: false,
            include_numbers: false,
            include_symbols: false,
            pronounceable: false,
            words: None,
        };
        let err = PasswordGenerator::generate_random(&no_sets).unwrap_err();
        assert!(err.to_string().contains("At least one character set"));

        let mut pronounceable = no_sets;
        pronounceable.pronounceable = true;
        let err = PasswordGenerator::generate_pronounceable(&pronounceable).unwrap_err();
        assert!(err
            .to_string()
            .contains("Pronounceable passwords require at least one letter set"));
    }

    #[test]
    fn generates_passphrase_with_requested_word_count() {
        let options = PasswordGeneratorOptions {
            words: Some(6),
            ..PasswordGeneratorOptions::default()
        };
        let passphrase = PasswordGenerator::generate(&options).unwrap();
        let words: Vec<&str> = passphrase.split('-').collect();
        assert_eq!(words.len(), 6);
        for word in &words {
            assert!(
                PasswordGenerator::wordlist().contains(word),
                "{word} is not in the EFF wordlist"
            );
        }
    }

    #[test]
    fn passphrase_word_count_must_be_between_3_and_10() {
        for word_count in [0, 2, 11] {
            let options = PasswordGeneratorOptions {
                words: Some(word_count),
                ..PasswordGeneratorOptions::default()
            };
            let err = PasswordGenerator::generate(&options).unwrap_err();
            assert!(
                err.to_string().contains("between 3 and 10"),
                "word count {word_count} should be rejected: {err}"
            );
        }

        // Both ends of the range generate.
        for word_count in [3, 10] {
            let options = PasswordGeneratorOptions {
                words: Some(word_count),
                ..PasswordGeneratorOptions::default()
            };
            let passphrase = PasswordGenerator::generate(&options).unwrap();
            assert_eq!(passphrase.split('-').count(), word_count);
        }
    }

    #[test]
    fn passphrase_and_pronounceable_are_mutually_exclusive() {
        let options = PasswordGeneratorOptions {
            pronounceable: true,
            words: Some(6),
            ..PasswordGeneratorOptions::default()
        };
        let err = PasswordGenerator::generate(&options).unwrap_err();
        assert!(err
            .to_string()
            .contains("Words mode cannot be combined with pronounceable"));
    }

    #[test]
    fn passphrase_ignores_length_and_set_validation() {
        // length 3 and no character sets would both fail in random mode; words
        // mode is self-contained and must not inherit those checks.
        let options = PasswordGeneratorOptions {
            length: 3,
            include_lowercase: false,
            include_uppercase: false,
            include_numbers: false,
            include_symbols: false,
            pronounceable: false,
            words: Some(5),
        };
        let passphrase = PasswordGenerator::generate(&options).unwrap();
        assert_eq!(passphrase.split('-').count(), 5);
    }

    #[test]
    fn eff_wordlist_parses_to_unique_lowercase_words() {
        let words = PasswordGenerator::wordlist();
        assert_eq!(words.len(), 7772, "EFF large wordlist word count");
        let mut sorted = words.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), words.len(), "wordlist contains duplicates");
        assert!(
            words
                .iter()
                .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase())),
            "every word must be a non-empty [a-z]+ token"
        );
    }

    #[test]
    fn default_options_have_words_disabled() {
        assert!(PasswordGeneratorOptions::default().words.is_none());
    }
}
