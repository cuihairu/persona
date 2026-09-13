use indicatif::{ProgressBar, ProgressStyle};

pub fn create_progress_bar(total: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(message.to_string());
    pb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_bar_carries_total_and_message() {
        let pb = create_progress_bar(42, "importing");
        assert_eq!(pb.length(), Some(42));
        assert_eq!(pb.message(), "importing");
        pb.finish_and_clear();
    }

    #[test]
    fn progress_bar_accepts_zero_total() {
        let pb = create_progress_bar(0, "nothing to do");
        assert_eq!(pb.length(), Some(0));
        pb.finish_and_clear();
    }
}
