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

/// The production [`PromptUi`] implementation lives in
/// [`crate::utils::terminal_ui`]; re-exported here so callers keep a single
/// import path.
pub use crate::utils::terminal_ui::TerminalUi;

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

    #[test]
    fn default_matches_new_and_empty_input_falls_back_to_default() {
        // `Default` must behave exactly like `new`.
        let ui = ScriptedUi::default();
        assert!(ui.exhausted());

        // An empty scripted answer means "accept the default".
        let ui = ScriptedUi::new().input("");
        let ui_dyn: &dyn super::PromptUi = &ui;
        assert_eq!(
            ui_dyn
                .input_with_default("name?", "fallback-name")
                .unwrap(),
            "fallback-name"
        );
        assert!(ui.exhausted());
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn select_index_beyond_options_is_rejected() {
        let ui = ScriptedUi::new().select(5);
        let ui_dyn: &dyn super::PromptUi = &ui;
        let _ = ui_dyn.select("pick", &["a", "b"], None).unwrap();
    }

    /// Which prompt kind should [`FailOn`] turn into an error.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum PromptKind {
        Input,
        InputWithDefault,
        Password,
        Confirm,
        Select,
        MultiSelect,
    }

    /// A [`PromptUi`](super::PromptUi) wrapper that fails exactly one prompt
    /// kind and delegates everything else to an inner UI. Tests use it to
    /// drive the `?`-error propagation paths of interactive flows, which the
    /// always-succeeding [`ScriptedUi`] cannot reach.
    pub struct FailOn<'a> {
        inner: &'a dyn super::PromptUi,
        kind: PromptKind,
    }

    impl<'a> FailOn<'a> {
        pub fn new(inner: &'a dyn super::PromptUi, kind: PromptKind) -> Self {
            Self { inner, kind }
        }

        fn fails(&self, kind: PromptKind) -> bool {
            self.kind == kind
        }
    }

    impl super::PromptUi for FailOn<'_> {
        fn input(
            &self,
            prompt: &str,
            initial: Option<&str>,
            allow_empty: bool,
        ) -> Result<String> {
            if self.fails(PromptKind::Input) {
                bail!("failing ui: input prompt: {}", prompt);
            }
            self.inner.input(prompt, initial, allow_empty)
        }

        fn input_with_default(&self, prompt: &str, default: &str) -> Result<String> {
            if self.fails(PromptKind::InputWithDefault) {
                bail!("failing ui: default input prompt: {}", prompt);
            }
            self.inner.input_with_default(prompt, default)
        }

        fn password(
            &self,
            prompt: &str,
            allow_empty: bool,
            confirmation: Option<(&str, &str)>,
        ) -> Result<String> {
            if self.fails(PromptKind::Password) {
                bail!("failing ui: password prompt: {}", prompt);
            }
            self.inner.password(prompt, allow_empty, confirmation)
        }

        fn confirm(&self, prompt: &str, default: bool) -> Result<bool> {
            if self.fails(PromptKind::Confirm) {
                bail!("failing ui: confirm prompt: {}", prompt);
            }
            self.inner.confirm(prompt, default)
        }

        fn select(&self, prompt: &str, options: &[&str], default: Option<usize>) -> Result<usize> {
            if self.fails(PromptKind::Select) {
                bail!("failing ui: select prompt: {}", prompt);
            }
            self.inner.select(prompt, options, default)
        }

        fn multi_select(&self, prompt: &str, options: &[&str]) -> Result<Vec<usize>> {
            if self.fails(PromptKind::MultiSelect) {
                bail!("failing ui: multi-select prompt: {}", prompt);
            }
            self.inner.multi_select(prompt, options)
        }
    }

    #[test]
    fn fail_on_only_fails_the_selected_kind() {
        let inner = ScriptedUi::new()
            .password("hunter2")
            .confirm(true)
            .input("typed");
        let ui = FailOn::new(&inner, PromptKind::Select);
        let ui_dyn: &dyn super::PromptUi = &ui;

        // Delegated kinds pass through to the inner UI.
        assert_eq!(ui_dyn.password("secret?", false, None).unwrap(), "hunter2");
        assert!(ui_dyn.confirm("yes?", true).unwrap());
        assert_eq!(ui_dyn.input("text?", None, false).unwrap(), "typed");

        // The selected kind errors.
        let err = ui_dyn
            .select("pick", &["a", "b"], None)
            .expect_err("select must fail");
        assert!(err.to_string().contains("failing ui: select prompt"));

        // A wrapper around an exhausted inner UI surfaces the inner panic.
        let empty = ScriptedUi::new();
        let ui = FailOn::new(&empty, PromptKind::Password);
        let ui_dyn: &dyn super::PromptUi = &ui;
        let err = ui_dyn
            .password("secret?", false, None)
            .expect_err("password must fail without consulting the inner UI");
        assert!(err.to_string().contains("failing ui: password prompt"));
        // FailOn bailed before consulting the inner UI, so its queue is intact.
        assert!(empty.exhausted());
    }
}
