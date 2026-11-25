//! Identity edit command: load → show current values → one of the three edit
//! paths (interactive / single field / arguments) → validate → confirm → save.
//!
//! # Module layout
//!
//! The types (`EditArgs` and the `Identity` edit snapshot) stay in this hub —
//! their private fields are read and written by every submodule and by the
//! tests; flow orchestration, field editing, custom attributes, display, and
//! persistence each live in their own submodule.

use clap::Args;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

mod attributes;
mod display;
mod fields;
mod flow;
mod persist;

pub use flow::execute;

#[cfg(test)]
mod tests;

#[derive(Args)]
pub struct EditArgs {
    /// Identity name to edit
    name: String,

    /// New identity type
    #[arg(long)]
    identity_type: Option<String>,

    /// New description
    #[arg(long)]
    description: Option<String>,

    /// New email address
    #[arg(long)]
    email: Option<String>,

    /// New phone number
    #[arg(long)]
    phone: Option<String>,

    /// Interactive editing mode
    #[arg(short, long)]
    interactive: bool,

    /// Edit specific field only
    #[arg(long)]
    field: Option<String>,

    /// New value for the field
    #[arg(long)]
    value: Option<String>,
}

#[derive(Debug, Clone)]
struct Identity {
    id: Option<Uuid>,
    name: String,
    identity_type: String,
    description: String,
    email: Option<String>,
    phone: Option<String>,
    tags: Vec<String>,
    attributes: HashMap<String, Value>,
    modified: String,
}
