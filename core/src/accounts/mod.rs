//! Client and contract types for the account domain (persona-server `/api/v1/accounts/*`).
//!
//! The placement discipline mirrors the E2EE sync track: networking and wire
//! live in core ([`remote`], a pure HTTP proxy), and the cryptography /
//! ceremony orchestration lives in core too ([`login`]; SRP math never
//! leaves core — the rendering layer does no password derivation at all).
//! Feature `accounts` (gated independently, like the other reqwest
//! consumers such as `remote-auth`).

pub mod login;
pub mod remote;
