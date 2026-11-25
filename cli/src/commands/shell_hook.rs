//! `persona shell-hook` (docs/CONTEXT_AWARE_DESIGN.md phase 2).
//!
//! Generates zsh/bash prompt snippets: the interactive shell calls
//! `persona suggest --short` before each prompt render (silent on failure or no
//! candidate), prefixing "⛵ <identity>" into PS1.
//!
//! The iron rule stays: the hook only changes prompt display and performs no
//! switching; confirmation goes through `persona use` (= the `persona switch`
//! alias, audited). When `PERSONA_NO_CONTEXT=1` the hook is inert as soon as it
//! is sourced (decided at source time).

/// bash snippet: PROMPT_COMMAND refreshes PERSONA_CTX_SUGGEST first, and the
/// `$PERSONA_CTX_SUGGEST` inlined into PS1 expands only at each prompt render —
/// it never accumulates or lags behind.
pub fn bash_snippet() -> &'static str {
    r#"# persona context suggestion (docs/CONTEXT_AWARE_DESIGN.md stage 2):
# shows the suggested identity in the prompt. Suggestion never switches
# identity — confirm with `persona use <name>`. Unset with
# PERSONA_NO_CONTEXT=1 before sourcing this snippet.
if [ -n "$PS1" ] && [ -z "$PERSONA_NO_CONTEXT" ]; then
  __persona_context_ps1() {
    command -v persona >/dev/null 2>&1 || return 0
    local s
    PERSONA_CTX_SUGGEST=""
    if s="$(persona suggest --short 2>/dev/null)" && [ -n "$s" ]; then
      PERSONA_CTX_SUGGEST=" ⛵ $s"
    fi
  }
  PROMPT_COMMAND="__persona_context_ps1${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
  PS1='$PERSONA_CTX_SUGGEST'"$PS1"
fi
"#
}

/// zsh snippet: precmd hook + prompt_subst, same semantics as bash.
pub fn zsh_snippet() -> &'static str {
    r#"# persona context suggestion (docs/CONTEXT_AWARE_DESIGN.md stage 2):
# shows the suggested identity in the prompt. Suggestion never switches
# identity — confirm with `persona use <name>`. Unset with
# PERSONA_NO_CONTEXT=1 before sourcing this snippet.
if [ -o interactive ] && [ -z "$PERSONA_NO_CONTEXT" ]; then
  setopt prompt_subst
  __persona_context_ps1() {
    command -v persona >/dev/null 2>&1 || return 0
    local s
    PERSONA_CTX_SUGGEST=""
    if s="$(persona suggest --short 2>/dev/null)" && [ -n "$s" ]; then
      PERSONA_CTX_SUGGEST=" ⛵ $s"
    fi
  }
  precmd_functions=(__persona_context_ps1 $precmd_functions)
  PROMPT='${PERSONA_CTX_SUGGEST}'"$PROMPT"
fi
"#
}

/// Probe the default target from `$SHELL` (basename containing zsh → zsh, otherwise bash).
fn detect_shell() -> &'static str {
    let shell = std::env::var("SHELL").unwrap_or_default();
    let base = shell.rsplit('/').next().unwrap_or("");
    if base.contains("zsh") {
        "zsh"
    } else {
        "bash"
    }
}

pub fn execute(shell: Option<&str>) -> anyhow::Result<()> {
    let target = shell
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| detect_shell().to_string());
    match target.as_str() {
        "bash" => print!("{}", bash_snippet()),
        "zsh" => print!("{}", zsh_snippet()),
        other => anyhow::bail!(
            "Unsupported shell '{other}'. Supported: bash, zsh (or omit to auto-detect)."
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_snippet_contains_hook_and_safety_gates() {
        let s = bash_snippet();
        assert!(
            s.contains("PS1='$PERSONA_CTX_SUGGEST'"),
            "PS1 prefix must re-expand at render time"
        );
        assert!(s.contains("PROMPT_COMMAND=\"__persona_context_ps1"));
        assert!(s.contains("suggest --short"));
        assert!(
            s.contains("PERSONA_NO_CONTEXT"),
            "opt-out gate must be documented in the snippet"
        );
        assert!(
            s.contains("persona use"),
            "snippet must point at the confirm path"
        );
    }

    #[test]
    fn zsh_snippet_uses_precmd_and_prompt_subst() {
        let s = zsh_snippet();
        assert!(s.contains("setopt prompt_subst"));
        assert!(s.contains("precmd_functions=(__persona_context_ps1"));
        assert!(s.contains("PROMPT='${PERSONA_CTX_SUGGEST}'"));
        assert!(s.contains("PERSONA_NO_CONTEXT"));
    }

    #[test]
    fn unknown_shell_is_rejected() {
        assert!(execute(Some("fish")).is_err());
        assert!(execute(Some("")).is_ok(), "empty falls back to auto-detect");
    }

    #[test]
    fn explicit_targets_are_accepted() {
        assert!(execute(Some("bash")).is_ok());
        assert!(execute(Some("ZSH")).is_ok(), "case-insensitive");
    }

    /// Feed the script to `bash -s` via stdin (with `-n`, syntax-check only), with
    /// `path` as the in-process PATH. Returns the child's full output for assertions.
    /// stdin is the only platform-independent way to feed the script: on Windows,
    /// msys bash cannot resolve `temp_dir()` file paths of the `C:\…`/`C:/…` form
    /// (argv from a non-msys parent skips MSYS path conversion, and all three forms
    /// `C:\`, `C:/`, `/c/` were observed to fail with "No such file or directory"),
    /// whereas stdin behaves identically on Linux/Windows.
    fn run_bash(script: &str, args: &[&str], path: &str) -> std::process::Output {
        use std::io::Write;
        let mut child = std::process::Command::new("bash")
            .args(args)
            .env("PATH", path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("bash available");
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(script.as_bytes())
            .expect("write script to bash stdin");
        child.wait_with_output().expect("bash run")
    }

    /// Dual-shell smoke (design acceptance): the generated snippet must pass the
    /// syntax check of its target shell and load plus invoke the refresh function
    /// once (no candidate → the variable stays empty).
    #[test]
    fn snippets_pass_shell_syntax_and_smoke_run() {
        // Smoke-test only when `bash` is a real bash (same rule as zsh below: optional
        // environment). On GitHub windows runners, `bash` on PATH is a WSL stub —
        // when no distro is installed it errors out on any argument (UTF-16 message),
        // so a `--version` probe failing → skip; the snippet's syntax itself is locked
        // by the same test on Linux CI.
        let bash_available = std::process::Command::new("bash")
            .arg("--version")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if bash_available {
            // Syntax check: the snippet is read via stdin, with no file path dependency.
            let out = run_bash(bash_snippet(), &["-n"], "/usr/bin:/bin");
            assert!(
                out.status.success(),
                "generated bash snippet must be syntactically valid: {}",
                String::from_utf8_lossy(&out.stderr)
            );

            // Load + invoke: set PS1 first so the load guard holds even under a
            // non-interactive `bash -s` (in non-interactive mode PS1 is unset by default,
            // the guard would skip the function definition, and the smoke test would idle).
            // No persona binary on PATH → command -v fails → return 0 with the variable
            // left empty (silent degradation). The `&&` chain makes "function undefined"
            // fail honestly as well.
            let smoke = format!(
                "PS1='$ '\n{}\n__persona_context_ps1 && test -z \"$PERSONA_CTX_SUGGEST\"\n",
                bash_snippet()
            );
            let out = run_bash(&smoke, &["-s"], "/usr/bin:/bin");
            assert!(
                out.status.success(),
                "bash hook must degrade to an empty suggestion var: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        // zsh: smoke-test only when installed (optional on CI/local). The zsh snippet is
        // sourced from a file (zsh has no Windows distro; only Linux/mac hit this
        // optional path, where temp_dir is a POSIX path).
        if let Ok(status) = std::process::Command::new("zsh").arg("--version").status() {
            if status.success() {
                let dir = std::env::temp_dir().join(format!("persona-hook-{}", std::process::id()));
                std::fs::create_dir_all(&dir).unwrap();
                let zsh_hook = dir.join("hook.zsh");
                std::fs::write(&zsh_hook, zsh_snippet()).unwrap();
                let ok = std::process::Command::new("zsh")
                    .arg("-n")
                    .arg(&zsh_hook)
                    .status()
                    .expect("zsh run")
                    .success();
                assert!(ok, "generated zsh snippet must be syntactically valid");
                std::fs::remove_dir_all(&dir).ok();
            }
        }
    }
}
