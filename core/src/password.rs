use crate::{PersonaError, Result};
use rand::{rngs::OsRng, seq::SliceRandom, Rng};

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

        let mut rng = OsRng;

        // Build a combined pool for general selection
        let combined: Vec<char> = pools.iter().flat_map(|set| set.chars()).collect();
        let mut password_chars = Vec::with_capacity(options.length);

        // Guarantee at least one character from each selected set
        for set in &pools {
            password_chars.push(Self::choose_random_char(set, &mut rng));
        }

        while password_chars.len() < options.length {
            let ch = combined[rng.gen_range(0..combined.len())];
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

        let mut rng = OsRng;
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

    fn choose_random_char(set: &str, rng: &mut OsRng) -> char {
        let bytes = set.as_bytes();
        let idx = rng.gen_range(0..bytes.len());
        bytes[idx] as char
    }

    fn inject_character_from_set(chars: &mut [char], set: &str, rng: &mut OsRng) {
        if chars.is_empty() {
            return;
        }

        let idx = rng.gen_range(0..chars.len());
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
}
