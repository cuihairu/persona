//! OS 级生物识别/用户确认 provider（Touch ID / Windows Hello / polkit）。
//!
//! 实现 core 的同步 [`BiometricProvider`] trait，而三个平台的系统弹框
//! API 全是阻塞或回调式——`run_with_timeout` 在专用短命线程上跑
//! ceremony 并限时收回结果，把阻塞限制在线程边界内（token_store 在
//! async 命令里同步调 keyring/zbus 是同一既成事实）。超时后线程悬挂
//! 至系统弹窗自行结束即退出（detached，每次 ceremony 一条短命线程，
//! 无泄漏累积）。
//!
//! 解锁屏 ceremony 没有活的 PersonaService，provider 挂在 AppState
//! （`types::AppState::biometric_provider`）；命令层调用时一律再包
//! `spawn_blocking`，不泊车 tokio worker。
//!
//! availability 探测 fail-closed：无 secret service / 无 polkit /
//! 非 三大桌面平台一律不可用，前端隐藏指纹入口。

use persona_core::{BiometricAuthResult, BiometricPlatform, BiometricPrompt, BiometricProvider};
use std::time::Duration;

/// 一次系统认证弹窗的最长等待（超时 = 用户放弃，视为失败）
const CEREMONY_TIMEOUT: Duration = Duration::from_secs(120);

/// availability 探测的最长等待——解锁屏 mount 就要查 status，坏掉的
/// 系统服务不能拖慢界面，超时按不可用处理（fail-closed）
const AVAILABILITY_TIMEOUT: Duration = Duration::from_secs(5);

/// 在专用线程上执行 `f` 并限时等待结果。
fn run_with_timeout<T, F>(f: F, timeout: Duration) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("persona-biometric".to_string())
        .spawn(move || {
            // 接收端超时放弃后线程随系统弹窗结束自然退出，send 失败无所谓
            let _ = tx.send(f());
        })
        .map_err(|e| format!("biometric thread spawn failed: {e}"))?;
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err("biometric prompt timed out".into()),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("biometric thread exited unexpectedly".into())
        }
    }
}

// ---------------------------------------------------------------------------
// 平台分发（各模块暴露 available/ceremony/platform_name 三个自由函数）
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as os;

#[cfg(target_os = "windows")]
mod windows_hello;
#[cfg(target_os = "windows")]
use windows_hello as os;

#[cfg(target_os = "linux")]
mod polkit;
#[cfg(target_os = "linux")]
use polkit as os;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
mod unsupported;
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
use unsupported as os;

/// trait 层回报的平台枚举（沿用 ssh-agent detect_platform 的既有映射）
fn result_platform() -> BiometricPlatform {
    #[cfg(target_os = "macos")]
    {
        BiometricPlatform::TouchId
    }
    #[cfg(target_os = "windows")]
    {
        BiometricPlatform::WindowsHello
    }
    #[cfg(target_os = "linux")]
    {
        BiometricPlatform::LinuxSecretService
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        BiometricPlatform::Unknown
    }
}

/// OS 直连的 biometric provider（解锁 ceremony 与 SSH agent 策略共用）。
///
/// `is_available` 忽略 `hint`（调用方对平台的猜测无关紧要，这里探测的
/// 就是本机真实认证栈）；`prompt.user_id` 同样被忽略——OS 认证的是
/// 登录会话用户，不是 vault 里的某个身份。
pub struct OsBiometricProvider;

impl BiometricProvider for OsBiometricProvider {
    fn is_available(&self, _hint: Option<BiometricPlatform>) -> bool {
        run_with_timeout(|| Ok(os::available()), AVAILABILITY_TIMEOUT).unwrap_or(false)
    }

    fn authenticate(&self, prompt: &BiometricPrompt) -> persona_core::Result<BiometricAuthResult> {
        let reason = prompt.reason.clone();
        run_with_timeout(move || os::ceremony(&reason), CEREMONY_TIMEOUT)
            .map_err(persona_core::PersonaError::AuthenticationFailed)?;
        Ok(BiometricAuthResult {
            user_id: prompt.user_id,
            verified: true,
            platform: result_platform(),
        })
    }
}

/// 前端 status 展示用的平台名（"touch-id" / "windows-hello" /
/// "linux-polkit" / "unsupported"）
pub fn platform_name() -> &'static str {
    os::platform_name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceremony_timeout_returns_error() {
        // 闭包睡过时限：run_with_timeout 必须超时返回错误而非挂死
        let result = run_with_timeout(
            || {
                std::thread::sleep(Duration::from_secs(6));
                Ok(())
            },
            Duration::from_secs(1),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timed out"));
    }

    #[test]
    fn ceremony_success_propagates_value() {
        let result = run_with_timeout(|| Ok(42u8), Duration::from_secs(5));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn availability_failure_is_false() {
        // 探测失败（错误或超时）一律 fail-closed 为不可用
        let probe: Result<bool, String> =
            run_with_timeout(|| Err("no secret service".into()), AVAILABILITY_TIMEOUT);
        assert!(!probe.unwrap_or(false));
    }
}
