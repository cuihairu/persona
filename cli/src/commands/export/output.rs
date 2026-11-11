use super::*;

pub(crate) fn compress_file(file_path: &Path, level: u8) -> Result<()> {
    println!("🗜️ Compressing file...");

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::fs::File;
    use std::io::Write;

    let src_path = file_path;
    let compressed_path = src_path.with_extension(format!(
        "{}.gz",
        src_path.extension().unwrap_or_default().to_string_lossy()
    ));

    let input = std::fs::read(src_path).context("Failed to read file for compression")?;
    let mut encoder = GzEncoder::new(
        File::create(&compressed_path).context("Failed to create gzip file")?,
        Compression::new(level.min(9) as u32),
    );
    encoder
        .write_all(&input)
        .context("Failed to write gzip data")?;
    encoder.finish().context("Failed to finish gzip")?;
    // Remove original
    std::fs::remove_file(src_path).ok();

    println!("{} File compressed (level {})", "✓".green(), level);
    Ok(())
}

// legacy helper removed; kept for back-compat if referenced

pub(crate) fn show_export_info(output_path: &Path) -> Result<()> {
    if let Ok(metadata) = std::fs::metadata(output_path) {
        let file_size = crate::utils::format_file_size(metadata.len());
        println!("  File size: {}", file_size.cyan());
    }

    println!();
    println!("{}", "Next steps:".dimmed());
    println!("  • Share the export file securely");
    println!(
        "  • Import on another system: {}",
        "persona import <file>".cyan()
    );
    println!("  • Store backup safely");

    Ok(())
}
