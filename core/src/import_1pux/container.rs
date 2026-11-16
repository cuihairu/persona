//! 1PUX 容器解包：ZIP 读取与 `export.attributes` / `export.data` 的
//! 反序列化（版本宽松校验，未知版本告警但继续）。

use std::io::{Cursor, Read};

use anyhow::{Context, Result};

use super::{ExportAttributes, ExportData, OnePasswordExport};

// ---------------------------------------------------------------------------
// Container parsing
// ---------------------------------------------------------------------------

/// Parse the raw bytes of a `.1pux` file (unencrypted ZIP).
pub fn parse_1pux(bytes: &[u8]) -> Result<OnePasswordExport> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .context("not a valid 1PUX archive (expected an unencrypted ZIP)")?;
    let attributes_json = read_zip_entry(&mut zip, "export.attributes")?;
    let data_json = read_zip_entry(&mut zip, "export.data")?;

    let attributes: ExportAttributes =
        serde_json::from_str(&attributes_json).context("export.attributes is not valid JSON")?;
    let data: ExportData =
        serde_json::from_str(&data_json).context("export.data is not valid JSON")?;

    // 1PUX version 3 is the only documented format; other versions are parsed
    // leniently with a warning rather than rejected.
    if attributes.version != Some(3) {
        tracing::warn!(
            version = ?attributes.version,
            "unexpected 1PUX format version (expected 3); parsing anyway"
        );
    }

    Ok(OnePasswordExport {
        accounts: data.accounts,
    })
}

fn read_zip_entry(zip: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str) -> Result<String> {
    let mut file = zip
        .by_name(name)
        .with_context(|| format!("missing {name} in 1PUX archive"))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .with_context(|| format!("failed to read {name} from 1PUX archive"))?;
    Ok(buf)
}
