//! The real terminal, backed by `dialoguer`.
//!
//! Every method blocks on interactive stdin/stdout and therefore cannot run
//! under a test harness; tests substitute the scripted implementation in
//! [`crate::utils::prompt::scripted`] instead. This file is excluded from
//! coverage measurement via `--ignore-filename-regex`.

use anyhow::Result;

use crate::utils::prompt::PromptUi;

/// The real terminal, backed by dialoguer.
pub struct TerminalUi;

impl PromptUi for TerminalUi {
    fn input(&self, prompt: &str, initial: Option<&str>, allow_empty: bool) -> Result<String> {
        let mut input = dialoguer::Input::<String>::new()
            .with_prompt(prompt)
            .allow_empty(allow_empty);
        if let Some(initial) = initial {
            input = input.with_initial_text(initial);
        }
        Ok(input.interact_text()?)
    }

    fn input_with_default(&self, prompt: &str, default: &str) -> Result<String> {
        Ok(dialoguer::Input::<String>::new()
            .with_prompt(prompt)
            .default(default.to_string())
            .show_default(false)
            .interact_text()?)
    }

    fn password(
        &self,
        prompt: &str,
        allow_empty: bool,
        confirmation: Option<(&str, &str)>,
    ) -> Result<String> {
        let mut password = dialoguer::Password::new()
            .with_prompt(prompt)
            .allow_empty_password(allow_empty);
        if let Some((confirm_prompt, mismatch)) = confirmation {
            password = password.with_confirmation(confirm_prompt, mismatch);
        }
        Ok(password.interact()?)
    }

    fn confirm(&self, prompt: &str, default: bool) -> Result<bool> {
        Ok(dialoguer::Confirm::new()
            .with_prompt(prompt)
            .default(default)
            .interact()?)
    }

    fn select(&self, prompt: &str, options: &[&str], default: Option<usize>) -> Result<usize> {
        let mut select = dialoguer::Select::new().with_prompt(prompt).items(options);
        if let Some(default) = default {
            select = select.default(default);
        }
        Ok(select.interact()?)
    }

    fn multi_select(&self, prompt: &str, options: &[&str]) -> Result<Vec<usize>> {
        Ok(dialoguer::MultiSelect::new()
            .with_prompt(prompt)
            .items(options)
            .interact()?)
    }
}
