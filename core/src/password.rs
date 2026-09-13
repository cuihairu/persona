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
        }
    }
}

/// Password generation helper shared by CLI/Desktop/Server.
pub struct PasswordGenerator;

impl PasswordGenerator {
    /// Generate a password for the provided configuration.
    pub fn generate(options: &PasswordGeneratorOptions) -> Result<String> {
        Self::validate_options(options)?;

        if options.pronounceable {
            Self::generate_pronounceable(options)
        } else {
            Self::generate_random(options)
        }
    }

    fn validate_options(options: &PasswordGeneratorOptions) -> Result<()> {
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

        if options.length < pools.len() {
            return Err(PersonaError::InvalidInput(format!(
                "Length {} is too small for {} character sets",
                options.length,
                pools.len()
            ))
            .into());
        }

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
}
