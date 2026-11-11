//! Account system API: registration, login (passkey + SRP fallback), device management, recovery codes.
//!
//! Zero-knowledge principle: master password/key never leaves the device. Server only stores
//! public verification material (passkey public keys, SRP salt+verifier, recovery code hashes).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::Utc;
use persona_core::auth::srp;
use persona_core::crypto::hashing::PasswordHasher;
use persona_core::crypto::passkey::{self, CLIENT_DATA_TYPE_GET};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use super::{ApiError, ErrorItem};
use crate::auth::{SrpChallengeEntry, SRP_CHALLENGE_TTL};
use crate::state::AppState;

mod account_srp;
mod devices;
mod recovery;
mod register;
mod sessions;
mod webauthn;

pub use account_srp::{account_srp_challenge, account_srp_register, account_srp_verify};
pub use devices::{authorize_device, list_account_devices, revoke_account_device};
pub use recovery::{generate_recovery_codes, verify_recovery_code};
pub use register::register_account;
pub use sessions::{create_account_session, revoke_account_session};
use sessions::{decode_field, validate_device_name};
use webauthn::WebauthnCeremony;
use webauthn::{
    decode_b64url_field, MAX_AUTHENTICATOR_DATA_BYTES, MAX_CLIENT_DATA_BYTES, MAX_SIGNATURE_BYTES,
};
pub use webauthn::{
    passkey_create_options, passkey_login_options, passkey_register, AccountWebauthnState,
};

#[cfg(test)]
mod tests;
