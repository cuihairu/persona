//! 身份字段编辑：交互菜单、单字段入口与参数直填三条路径，
//! 以及各字段（类型/描述/邮箱/电话/标签）的编辑实现。

use anyhow::Result;
use colored::*;

use crate::utils::prompt::PromptUi;

use super::attributes::edit_custom_attributes;
use super::{EditArgs, Identity};

pub(super) fn edit_interactive(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let fields = [
        "Type",
        "Description",
        "Email",
        "Phone",
        "Tags",
        "Custom Attributes",
        "Done",
    ];

    loop {
        let selection = ui.select("What would you like to edit?", &fields, None)?;

        match selection {
            0 => edit_identity_type(identity, ui)?,
            1 => edit_description(identity, ui)?,
            2 => edit_email(identity, ui)?,
            3 => edit_phone(identity, ui)?,
            4 => edit_tags(identity, ui)?,
            5 => edit_custom_attributes(identity, ui)?,
            6 => break,
            _ => unreachable!(),
        }

        println!();
    }

    Ok(())
}

pub(super) fn edit_single_field(
    identity: &mut Identity,
    field: &str,
    value: Option<String>,
    ui: &dyn PromptUi,
) -> Result<()> {
    match field.to_lowercase().as_str() {
        "type" => {
            if let Some(new_type) = value {
                identity.identity_type = new_type;
            } else {
                edit_identity_type(identity, ui)?;
            }
        }
        "description" => {
            if let Some(new_desc) = value {
                identity.description = new_desc;
            } else {
                edit_description(identity, ui)?;
            }
        }
        "email" => {
            if let Some(new_email) = value {
                identity.email = if new_email.is_empty() {
                    None
                } else {
                    Some(new_email)
                };
            } else {
                edit_email(identity, ui)?;
            }
        }
        "phone" => {
            if let Some(new_phone) = value {
                identity.phone = if new_phone.is_empty() {
                    None
                } else {
                    Some(new_phone)
                };
            } else {
                edit_phone(identity, ui)?;
            }
        }
        _ => anyhow::bail!("Unknown field: {}", field),
    }

    Ok(())
}

pub(super) fn edit_from_args(identity: &mut Identity, args: &EditArgs) -> Result<()> {
    if let Some(ref new_type) = args.identity_type {
        identity.identity_type = new_type.clone();
    }

    if let Some(ref new_desc) = args.description {
        identity.description = new_desc.clone();
    }

    if let Some(ref new_email) = args.email {
        identity.email = if new_email.is_empty() {
            None
        } else {
            Some(new_email.clone())
        };
    }

    if let Some(ref new_phone) = args.phone {
        identity.phone = if new_phone.is_empty() {
            None
        } else {
            Some(new_phone.clone())
        };
    }

    Ok(())
}

pub(super) fn edit_identity_type(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let types = [
        "personal",
        "work",
        "social",
        "gaming",
        "shopping",
        "financial",
        "healthcare",
        "education",
        "other",
    ];

    let current_index = types
        .iter()
        .position(|&t| t == identity.identity_type)
        .unwrap_or(0);

    let selection = ui.select("Select identity type", &types, Some(current_index))?;

    identity.identity_type = types[selection].to_string();
    println!(
        "{} Type updated to: {}",
        "✓".green(),
        identity.identity_type.cyan()
    );

    Ok(())
}

fn edit_description(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let new_description = ui.input("Description", Some(&identity.description), false)?;

    identity.description = new_description;
    println!("{} Description updated", "✓".green());

    Ok(())
}

fn edit_email(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let current_email = identity.email.as_deref().unwrap_or("");
    let new_email = ui.input("Email (leave empty to remove)", Some(current_email), true)?;

    identity.email = if new_email.is_empty() {
        None
    } else {
        Some(new_email)
    };
    println!("{} Email updated", "✓".green());

    Ok(())
}

fn edit_phone(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let current_phone = identity.phone.as_deref().unwrap_or("");
    let new_phone = ui.input("Phone (leave empty to remove)", Some(current_phone), true)?;

    identity.phone = if new_phone.is_empty() {
        None
    } else {
        Some(new_phone)
    };
    println!("{} Phone updated", "✓".green());

    Ok(())
}

fn edit_tags(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let current_tags = identity.tags.join(", ");
    let new_tags = ui.input("Tags (comma-separated)", Some(&current_tags), true)?;

    identity.tags = new_tags
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    println!("{} Tags updated", "✓".green());

    Ok(())
}
