//! Import file format parsing: dispatch JSON / YAML / CSV by extension and
//! produce a uniform `ImportData` snapshot.

use anyhow::{Context, Result};
use std::path::Path;

use super::{ImportData, ImportIdentity};

pub(super) fn parse_import_file(file_path: &Path) -> Result<ImportData> {
    let content = std::fs::read_to_string(file_path).context("Failed to read import file")?;

    // Determine format by extension
    let format = file_path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("json");

    match format {
        "json" => parse_json_import(&content),
        "yaml" | "yml" => parse_yaml_import(&content),
        "csv" => parse_csv_import(&content),
        _ => anyhow::bail!("Unsupported import format: {}", format),
    }
}

pub(super) fn parse_json_import(content: &str) -> Result<ImportData> {
    let json_value: serde_json::Value =
        serde_json::from_str(content).context("Failed to parse JSON import file")?;

    let export_info = json_value
        .get("export_info")
        .context("Missing export_info in import file")?;

    let version = export_info
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let created = export_info
        .get("created")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let identities_array = json_value
        .get("identities")
        .and_then(|v| v.as_array())
        .context("Missing or invalid identities array")?;

    let mut identities = Vec::new();
    for identity_value in identities_array {
        let identity = ImportIdentity {
            name: identity_value
                .get("name")
                .and_then(|v| v.as_str())
                .context("Missing identity name")?
                .to_string(),
            identity_type: identity_value
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("personal")
                .to_string(),
            description: identity_value
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            email: identity_value
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            phone: identity_value
                .get("phone")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            tags: identity_value
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default(),
        };
        identities.push(identity);
    }

    Ok(ImportData {
        version,
        created,
        identities,
    })
}

pub(super) fn parse_yaml_import(content: &str) -> Result<ImportData> {
    let yaml_value: serde_yaml::Value =
        serde_yaml::from_str(content).context("Failed to parse YAML import file")?;

    // Convert YAML to JSON for easier processing
    let json_value: serde_json::Value =
        serde_json::to_value(yaml_value).context("Failed to convert YAML to JSON")?;

    parse_json_import(&serde_json::to_string(&json_value)?)
}

pub(super) fn parse_csv_import(content: &str) -> Result<ImportData> {
    let mut identities = Vec::new();
    let mut lines = content.lines();

    // Skip header
    lines.next();

    for line in lines {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() >= 4 {
            let identity = ImportIdentity {
                name: fields[0].to_string(),
                identity_type: fields[1].to_string(),
                description: fields[2].to_string(),
                email: if fields.len() > 3 && !fields[3].is_empty() {
                    Some(fields[3].to_string())
                } else {
                    None
                },
                phone: None,
                tags: Vec::new(),
            };
            identities.push(identity);
        }
    }

    Ok(ImportData {
        version: "csv".to_string(),
        created: chrono::Utc::now().to_rfc3339(),
        identities,
    })
}
