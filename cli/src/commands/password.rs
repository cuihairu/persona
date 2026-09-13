use std::collections::HashSet;

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use colored::*;
use persona_core::{PasswordGenerator, PasswordGeneratorOptions};

use crate::config::CliConfig;

#[derive(Args, Clone)]
pub struct PasswordArgs {
    #[command(subcommand)]
    command: PasswordCommand,
}

#[derive(Subcommand, Clone)]
pub enum PasswordCommand {
    /// Generate one or more passwords
    Generate(GenerateArgs),
}

#[derive(Args, Clone)]
pub struct GenerateArgs {
    /// Total password length (characters)
    #[arg(short, long, default_value = "16")]
    pub length: usize,

    /// Character sets to include (repeat flag or comma separated)
    #[arg(
        long = "set",
        value_enum,
        value_delimiter = ',',
        default_values_t = vec![
            CharacterSet::Lowercase,
            CharacterSet::Uppercase,
            CharacterSet::Digits,
            CharacterSet::Symbols
        ]
    )]
    pub sets: Vec<CharacterSet>,

    /// Generate pronounceable output (alternating consonants/vowels)
    #[arg(long)]
    pub pronounceable: bool,

    /// Number of passwords to generate
    #[arg(long, default_value = "1")]
    pub count: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, ValueEnum)]
pub enum CharacterSet {
    Lowercase,
    Uppercase,
    Digits,
    Symbols,
}

pub async fn execute(args: PasswordArgs, _config: &CliConfig) -> Result<()> {
    match args.command {
        PasswordCommand::Generate(opts) => generate_password(opts),
    }
}

fn generate_password(args: GenerateArgs) -> Result<()> {
    let selected: HashSet<CharacterSet> = args.sets.into_iter().collect();
    let include_lowercase = selected.contains(&CharacterSet::Lowercase);
    let include_uppercase = selected.contains(&CharacterSet::Uppercase);
    let include_numbers = selected.contains(&CharacterSet::Digits);
    let include_symbols = selected.contains(&CharacterSet::Symbols);

    let options = PasswordGeneratorOptions {
        length: args.length,
        include_lowercase,
        include_uppercase,
        include_numbers,
        include_symbols,
        pronounceable: args.pronounceable,
    };

    for idx in 1..=args.count {
        let password = PasswordGenerator::generate(&options)?;
        if args.count == 1 {
            println!(
                "{} Generated password (length {}): {}",
                "✓".green().bold(),
                args.length,
                password.cyan().bold()
            );
        } else {
            println!(
                "{} {}",
                format!("[{}]", idx).dimmed(),
                password.cyan().bold()
            );
        }
    }

    if args.pronounceable {
        println!(
            "{} Pronounceable mode enabled – alternating consonant/vowel pattern.",
            "ℹ".blue()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;

    fn generate_args(
        length: usize,
        sets: Vec<CharacterSet>,
        pronounceable: bool,
        count: usize,
    ) -> GenerateArgs {
        GenerateArgs {
            length,
            sets,
            pronounceable,
            count,
        }
    }

    #[tokio::test]
    async fn generate_single_default_password() {
        let config = CliConfig::default();
        let args = PasswordArgs {
            command: PasswordCommand::Generate(generate_args(
                20,
                vec![
                    CharacterSet::Lowercase,
                    CharacterSet::Uppercase,
                    CharacterSet::Digits,
                    CharacterSet::Symbols,
                ],
                false,
                1,
            )),
        };
        execute(args, &config)
            .await
            .expect("default generation works");
    }

    #[tokio::test]
    async fn generate_multiple_and_pronounceable_and_single_set() {
        let config = CliConfig::default();

        // Multiple passwords.
        execute(
            PasswordArgs {
                command: PasswordCommand::Generate(generate_args(
                    16,
                    vec![CharacterSet::Lowercase, CharacterSet::Digits],
                    false,
                    3,
                )),
            },
            &config,
        )
        .await
        .unwrap();

        // Pronounceable mode takes the alternate branch.
        execute(
            PasswordArgs {
                command: PasswordCommand::Generate(generate_args(
                    12,
                    vec![CharacterSet::Lowercase],
                    true,
                    1,
                )),
            },
            &config,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn duplicate_sets_collapse_via_hash_set() {
        let config = CliConfig::default();
        // Repeated flags deduplicate through the HashSet.
        execute(
            PasswordArgs {
                command: PasswordCommand::Generate(generate_args(
                    8,
                    vec![CharacterSet::Digits, CharacterSet::Digits],
                    false,
                    1,
                )),
            },
            &config,
        )
        .await
        .unwrap();
    }
}
