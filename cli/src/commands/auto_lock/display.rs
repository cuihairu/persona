//! 展示与解析助手：`OutputFormatter` 着色输出与用例标签解析。

use anyhow::{bail, Result};
use colored::*;
use persona_core::models::auto_lock_policy::AutoLockUseCase;

pub(super) fn parse_use_case_label(label: &str) -> Result<AutoLockUseCase> {
    match label.to_lowercase().as_str() {
        "personal" | "personal-device" | "personal_device" => Ok(AutoLockUseCase::PersonalDevice),
        "corporate" | "desktop" | "corporate-desktop" | "corporate_desktop" => {
            Ok(AutoLockUseCase::CorporateDesktop)
        }
        "public" | "kiosk" | "public-kiosk" | "public_kiosk" => Ok(AutoLockUseCase::PublicKiosk),
        "developer" | "dev" | "developer-environment" | "developer_environment" => {
            Ok(AutoLockUseCase::DeveloperEnvironment)
        }
        "high" | "high-security" | "high_security" | "facility" => {
            Ok(AutoLockUseCase::HighSecurityFacility)
        }
        other => bail!("Unsupported use case '{}'", other),
    }
}

#[derive(Default)]
pub(super) struct OutputFormatter;

impl OutputFormatter {
    pub(super) fn print_info(&self, message: &str) {
        println!("{}", message.cyan());
    }

    pub(super) fn print_output(&self, message: &str) {
        println!("{}", message);
    }

    pub(super) fn print_success(&self, message: &str) {
        println!("{} {}", "✓".green().bold(), message);
    }

    pub(super) fn print_warning(&self, message: &str) {
        println!("{} {}", "⚠".yellow().bold(), message);
    }

    pub(super) fn print_error(&self, message: &str) {
        println!("{} {}", "✗".red().bold(), message.red());
    }
}
