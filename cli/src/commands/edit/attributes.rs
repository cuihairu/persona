//! 自定义属性编辑：添加 / 改值 / 多选移除的交互子菜单。

use anyhow::Result;
use colored::*;
use serde_json::Value;

use crate::utils::prompt::PromptUi;

use super::Identity;

pub(super) fn edit_custom_attributes(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let actions = [
        "Add new attribute",
        "Edit existing attribute",
        "Remove attribute",
        "Done",
    ];

    loop {
        let selection = ui.select("Attribute action", &actions, None)?;

        match selection {
            0 => add_custom_attribute(identity, ui)?,
            1 => edit_existing_attribute(identity, ui)?,
            2 => remove_custom_attribute(identity, ui)?,
            3 => break,
            _ => unreachable!(),
        }
    }

    Ok(())
}

fn add_custom_attribute(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let key = ui.input("Attribute name", None, false)?;

    let value = ui.input(&format!("Value for '{}'", key), None, false)?;

    identity
        .attributes
        .insert(key.clone(), Value::String(value));
    println!("{} Added attribute: {}", "✓".green(), key.cyan());

    Ok(())
}

pub(super) fn edit_existing_attribute(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    if identity.attributes.is_empty() {
        println!("{}", "No custom attributes to edit".yellow());
        return Ok(());
    }

    let keys: Vec<String> = identity.attributes.keys().cloned().collect();
    let selection = ui.select(
        "Select attribute to edit",
        &keys.iter().map(String::as_str).collect::<Vec<_>>(),
        None,
    )?;

    let key = &keys[selection];
    let current_value = identity
        .attributes
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let new_value = ui.input(
        &format!("New value for '{}'", key),
        Some(current_value),
        false,
    )?;

    identity
        .attributes
        .insert(key.clone(), Value::String(new_value));
    println!("{} Updated attribute: {}", "✓".green(), key.cyan());

    Ok(())
}

pub(super) fn remove_custom_attribute(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    if identity.attributes.is_empty() {
        println!("{}", "No custom attributes to remove".yellow());
        return Ok(());
    }

    let keys: Vec<String> = identity.attributes.keys().cloned().collect();
    let selections = ui.multi_select(
        "Select attributes to remove",
        &keys.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;

    for &index in &selections {
        let key = &keys[index];
        identity.attributes.remove(key);
        println!("{} Removed attribute: {}", "✓".green(), key.cyan());
    }

    Ok(())
}
