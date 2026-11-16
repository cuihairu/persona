//! Policy management for SSH Agent
//!
//! Provides fine-grained control over SSH key usage:
//! - Per-host restrictions
//! - Per-key policies
//! - Time-based restrictions
//! - Usage counting and rate limiting

mod enforcer;
mod model;

pub use enforcer::*;
pub use model::*;

#[cfg(test)]
mod tests;
