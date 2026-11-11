use super::*;

#[derive(Tabled)]
struct CustomFieldRow {
    #[tabled(rename = "Type")]
    field_type: String,
    #[tabled(rename = "Section")]
    section: String,
    #[tabled(rename = "Label")]
    label: String,
    #[tabled(rename = "Value")]
    value: String,
}

fn custom_field_type_name(t: CustomFieldType) -> &'static str {
    match t {
        CustomFieldType::Text => "text",
        CustomFieldType::Concealed => "concealed",
        CustomFieldType::Date => "date",
    }
}

/// `TYPE:SECTION:LABEL=VALUE` 解析（1Password 对齐的结构化字段）。
/// SECTION 可空（`text::Notes=hello`）且不允许含 `:`；首个 `=` 后全归
/// VALUE（值里可以再带 `=`）；label 非空；新字段 id 由 core 生成。
pub(crate) fn parse_field_spec(spec: &str) -> Result<CustomField> {
    let Some((head, value)) = spec.split_once('=') else {
        bail!("invalid field spec `{spec}`: expected TYPE:SECTION:LABEL=VALUE");
    };
    let parts: Vec<&str> = head.splitn(3, ':').collect();
    if parts.len() != 3 {
        bail!(
            "invalid field spec `{spec}`: expected TYPE:SECTION:LABEL=VALUE (section may be empty)"
        );
    }
    let field_type = match parts[0] {
        "text" => CustomFieldType::Text,
        "concealed" => CustomFieldType::Concealed,
        "date" => CustomFieldType::Date,
        other => bail!("unknown field type `{other}` in `{spec}` (text|concealed|date)"),
    };
    if parts[2].trim().is_empty() {
        bail!("invalid field spec `{spec}`: label must not be empty");
    }
    let mut field = new_custom_field(parts[2].trim(), value, field_type);
    let section = parts[1].trim();
    field.section = if section.is_empty() {
        None
    } else {
        Some(section.to_string())
    };
    Ok(field)
}

pub(crate) async fn list_custom_fields_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    id: Uuid,
    reveal: bool,
) -> Result<()> {
    let service = init_service(config, ui).await?;
    let fields = service
        .custom_fields(&id)
        .await
        .into_anyhow()
        .context("Failed to read custom fields")?;
    if fields.is_empty() {
        println!("{}", "No custom fields.".yellow());
        return Ok(());
    }

    let mut show_concealed = false;
    if reveal
        && fields
            .iter()
            .any(|f| f.field_type == CustomFieldType::Concealed)
    {
        show_concealed = ui.confirm("Reveal concealed values? (visible on screen)", false)?;
    }

    let rows: Vec<CustomFieldRow> = fields
        .iter()
        .map(|f| CustomFieldRow {
            field_type: custom_field_type_name(f.field_type).to_string(),
            section: f.section.clone().unwrap_or_default(),
            label: f.label.clone(),
            value: if f.field_type == CustomFieldType::Concealed && !show_concealed {
                "••••••••".to_string()
            } else {
                f.value.clone()
            },
        })
        .collect();
    println!("{}", Table::new(rows));
    Ok(())
}

pub(crate) async fn set_custom_fields_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    id: Uuid,
    specs: Vec<String>,
    clear: bool,
) -> Result<()> {
    if clear && !specs.is_empty() {
        bail!("--clear removes all fields; do not combine it with --field");
    }
    if !clear && specs.is_empty() {
        bail!("nothing to set: pass --field TYPE:SECTION:LABEL=VALUE (repeatable) or --clear to remove all");
    }
    let mut fields = Vec::with_capacity(specs.len());
    for spec in &specs {
        fields.push(parse_field_spec(spec)?);
    }
    let service = init_service(config, ui).await?;
    // 整表替换语义：未列出的既有字段会被移除
    service
        .set_custom_fields(&id, fields)
        .await
        .into_anyhow()
        .context("Failed to save custom fields")?;
    println!("{} Custom fields saved for {}", "✓".green(), id);
    Ok(())
}
