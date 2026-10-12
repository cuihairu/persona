//! `persona shell-hook`（docs/CONTEXT_AWARE_DESIGN.md 阶段 2）。
//!
//! 生成 zsh/bash 提示片段：交互 shell 在每次渲染提示符前调用
//! `persona suggest --short`（失败/无候选静默），把「⛵ <分身>」前缀进 PS1。
//!
//! 铁律不变：hook 只改提示符显示，不执行任何切换；确认走 `persona use`
//! （= `persona switch` 别名，落审计）。`PERSONA_NO_CONTEXT=1` 时 hook
//! 装载即不生效（source 时间判定）。

/// bash 片段：PROMPT_COMMAND 先刷新 PERSONA_CTX_SUGGEST，PS1 里内联的
/// `$PERSONA_CTX_SUGGEST` 在每次提示符渲染时才展开——不会叠加或滞后。
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

/// zsh 片段：precmd 钩子 + prompt_subst，同 bash 语义。
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

/// 按 `$SHELL` 探测默认目标（basename 含 zsh → zsh，否则 bash）。
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

    /// 双 shell 冒烟（设计验收）：生成的片段必须通过对应 shell 的语法检查，
    /// 并在非交互下能 source + 调一次刷新函数（无候选 → 变量保持空）。
    #[test]
    fn snippets_pass_shell_syntax_and_smoke_run() {
        let dir = std::env::temp_dir().join(format!("persona-hook-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // `bash` 必须是真 bash 才冒烟（与下面 zsh 同规：可选环境）。GitHub
        // windows runner 的 PATH 上 `bash` 是 WSL stub——没装发行版时对任何
        // 参数都报错退出（UTF-16 提示），`--version` 探测不过 → 跳过；片段
        // 语法本身由 Linux CI 的同测试锁定。
        let bash_available = std::process::Command::new("bash")
            .arg("--version")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if bash_available {
            let bash_hook = dir.join("hook.sh");
            std::fs::write(&bash_hook, bash_snippet()).unwrap();
            let ok = std::process::Command::new("bash")
                .arg("-n")
                .arg(&bash_hook)
                .status()
                .expect("bash available")
                .success();
            assert!(ok, "generated bash snippet must be syntactically valid");

            // Source + direct call: 命令失败也必须把变量清空（静默降级）。
            let probe = format!(
                "source '{}'; __persona_context_ps1; test -z \"$PERSONA_CTX_SUGGEST\"",
                bash_hook.display()
            );
            // PATH 上没有 persona 二进制 → command -v 失败 → 变量保持空。
            let ok = std::process::Command::new("bash")
                .arg("-c")
                .arg(&probe)
                .env("PATH", "/usr/bin:/bin")
                .status()
                .expect("bash smoke run")
                .success();
            assert!(ok, "bash hook must degrade to an empty suggestion var");
        }

        // zsh：装了才冒烟（CI/本机可选）。
        if let Ok(status) = std::process::Command::new("zsh").arg("--version").status() {
            if status.success() {
                let zsh_hook = dir.join("hook.zsh");
                std::fs::write(&zsh_hook, zsh_snippet()).unwrap();
                let ok = std::process::Command::new("zsh")
                    .arg("-n")
                    .arg(&zsh_hook)
                    .status()
                    .expect("zsh run")
                    .success();
                assert!(ok, "generated zsh snippet must be syntactically valid");
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
