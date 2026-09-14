use anyhow::Result;

/// Terminal interaction seam.
///
/// Production code drives the real terminal through [`TerminalUi`] (dialoguer);
/// tests substitute a scripted implementation so interactive flows run
/// head-less and every prompt branch stays covered.
pub trait PromptUi {
    /// Free-form text input. `initial` seeds the editable value; when
    /// `allow_empty` is false an empty answer is rejected.
    fn input(&self, prompt: &str, initial: Option<&str>, allow_empty: bool) -> Result<String>;

    /// Text input that falls back to `default` when the user just presses
    /// Enter.
    fn input_with_default(&self, prompt: &str, default: &str) -> Result<String>;

    /// Hidden (echo-suppressed) input. `allow_empty` permits submitting an
    /// empty value; `confirmation` optionally asks the user to repeat the
    /// value: `(prompt, mismatch message)`.
    fn password(
        &self,
        prompt: &str,
        allow_empty: bool,
        confirmation: Option<(&str, &str)>,
    ) -> Result<String>;

    /// Yes/no question; `default` is the answer for a bare Enter.
    fn confirm(&self, prompt: &str, default: bool) -> Result<bool>;

    /// Single choice out of `options`; `default` pre-selects an entry.
    fn select(&self, prompt: &str, options: &[&str], default: Option<usize>) -> Result<usize>;

    /// Multiple choices; returns the selected indices.
    fn multi_select(&self, prompt: &str, options: &[&str]) -> Result<Vec<usize>>;
}

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

#[cfg(test)]
pub mod scripted {
    use super::PromptUi;
    use anyhow::{bail, Result};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// A queue of pre-recorded answers for one [`PromptUi`] kind. Popping from
    /// an exhausted queue panics with the offending prompt, which keeps
    /// test scripts honest about the interaction order.
    struct Queue<T> {
        answers: Mutex<VecDeque<T>>,
        kind: &'static str,
    }

    impl<T> Queue<T> {
        fn new(kind: &'static str) -> Self {
            Self {
                answers: Mutex::new(VecDeque::new()),
                kind,
            }
        }

        fn push(&self, answer: T) -> &Self {
            self.answers.lock().unwrap().push_back(answer);
            self
        }

        fn pop(&self, prompt: &str) -> T {
            let mut answers = self.answers.lock().unwrap();
            answers.pop_front().unwrap_or_else(|| {
                panic!("scripted UI: unexpected {} prompt: {}", self.kind, prompt)
            })
        }
    }

    /// Scripted [`PromptUi`](super::PromptUi) for tests: every queue must be
    /// pre-loaded with answers in interaction order.
    pub struct ScriptedUi {
        inputs: Queue<String>,
        passwords: Queue<String>,
        confirms: Queue<bool>,
        selects: Queue<usize>,
        multi_selects: Queue<Vec<usize>>,
    }

    impl Default for ScriptedUi {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ScriptedUi {
        pub fn new() -> Self {
            Self {
                inputs: Queue::new("input"),
                passwords: Queue::new("password"),
                confirms: Queue::new("confirm"),
                selects: Queue::new("select"),
                multi_selects: Queue::new("multi_select"),
            }
        }

        pub fn input(self, answer: &str) -> Self {
            self.inputs.push(answer.to_string());
            self
        }

        pub fn password(self, answer: &str) -> Self {
            self.passwords.push(answer.to_string());
            self
        }

        pub fn confirm(self, answer: bool) -> Self {
            self.confirms.push(answer);
            self
        }

        pub fn select(self, answer: usize) -> Self {
            self.selects.push(answer);
            self
        }

        pub fn multi_select(self, answers: &[usize]) -> Self {
            self.multi_selects.push(answers.to_vec());
            self
        }

        /// True when no scripted answer of any kind is left.
        pub fn exhausted(&self) -> bool {
            self.inputs.answers.lock().unwrap().is_empty()
                && self.passwords.answers.lock().unwrap().is_empty()
                && self.confirms.answers.lock().unwrap().is_empty()
                && self.selects.answers.lock().unwrap().is_empty()
                && self.multi_selects.answers.lock().unwrap().is_empty()
        }
    }

    impl PromptUi for ScriptedUi {
        fn input(
            &self,
            prompt: &str,
            _initial: Option<&str>,
            _allow_empty: bool,
        ) -> Result<String> {
            Ok(self.inputs.pop(prompt))
        }

        fn input_with_default(&self, prompt: &str, default: &str) -> Result<String> {
            // An empty scripted answer means "accept the default".
            let scripted = self.inputs.pop(prompt);
            Ok(if scripted.is_empty() {
                default.to_string()
            } else {
                scripted
            })
        }

        fn password(
            &self,
            prompt: &str,
            _allow_empty: bool,
            _confirmation: Option<(&str, &str)>,
        ) -> Result<String> {
            Ok(self.passwords.pop(prompt))
        }

        fn confirm(&self, prompt: &str, _default: bool) -> Result<bool> {
            Ok(self.confirms.pop(prompt))
        }

        fn select(&self, prompt: &str, options: &[&str], _default: Option<usize>) -> Result<usize> {
            let index = self.selects.pop(prompt);
            if index >= options.len() {
                bail!(
                    "scripted UI: select index {} out of range for prompt: {}",
                    index,
                    prompt
                );
            }
            Ok(index)
        }

        fn multi_select(&self, prompt: &str, _options: &[&str]) -> Result<Vec<usize>> {
            Ok(self.multi_selects.pop(prompt))
        }
    }

    #[test]
    fn exhausted_reports_when_every_queue_is_drained() {
        assert!(ScriptedUi::new().exhausted());

        let ui = ScriptedUi::new().confirm(true).select(1);
        assert!(!ui.exhausted());
        drop(ui);
    }

    #[test]
    fn scripted_answers_are_served_in_interaction_order() {
        let ui = ScriptedUi::new()
            .confirm(true)
            .select(1)
            .input("typed answer")
            .password("hunter2")
            .multi_select(&[0, 2]);

        // Go through `dyn PromptUi` so the trait methods (not the builders)
        // are exercised.
        let ui_dyn: &dyn super::PromptUi = &ui;
        assert!(ui_dyn.confirm("yes?", true).unwrap());
        assert_eq!(ui_dyn.select("pick", &["a", "b"], None).unwrap(), 1);
        assert_eq!(ui_dyn.input("text?", None, false).unwrap(), "typed answer");
        assert_eq!(ui_dyn.password("secret?", false, None).unwrap(), "hunter2");
        assert_eq!(
            ui_dyn.multi_select("many?", &["a", "b", "c"]).unwrap(),
            vec![0, 2]
        );
        assert!(ui.exhausted());
    }

    #[test]
    #[should_panic(expected = "unexpected confirm prompt")]
    fn popping_from_an_empty_queue_panics_with_the_prompt() {
        let ui = ScriptedUi::new();
        let ui_dyn: &dyn super::PromptUi = &ui;
        let _ = ui_dyn.confirm("nobody scripted me", true);
    }
}
