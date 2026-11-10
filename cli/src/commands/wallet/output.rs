use super::*;

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
