//! Command wire requests, `ApiResponse<T>` and the `CredentialDataRequest` domain.

use persona_core::*;
use serde::{Deserialize, Serialize};

/// Response structure for API calls
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    /// Machine-readable error code ("REAUTH_REQUIRED" / "SERVICE_LOCKED"),
    /// used by the frontend to route handling
    pub error_code: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            error_code: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
            error_code: None,
        }
    }

    pub fn error_with_code(error_code: String, message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
            error_code: Some(error_code),
        }
    }

    /// With `code = None` this is equivalent to [`Self::error`]; with a code
    /// present it is equivalent to [`Self::error_with_code`].
    /// For use at boundary convergence points: an error can sometimes be
    /// mapped to an error code and sometimes only the message can be passed
    /// through.
    pub fn error_maybe_coded(error_code: Option<String>, message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
            error_code,
        }
    }
}

/// Initialization request
#[derive(Debug, Deserialize)]
pub struct InitRequest {
    pub master_password: String,
    pub db_path: Option<String>,
}

/// Change-master-password request (parameters for the change-password
/// command; the old password exists only in this request — never persisted,
/// never logged)
#[derive(Debug, Deserialize)]
pub struct ChangeMasterPasswordRequest {
    pub old_password: String,
    pub new_password: String,
    pub db_path: Option<String>,
}

/// Result of `generate_password_advanced`: candidate passwords plus an entropy
/// estimate and character-pool size for UI display (a display aid, not a
/// security guarantee; the character sets come from the same source as the
/// core generator).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPasswords {
    pub passwords: Vec<String>,
    pub entropy_bits: f64,
    pub pool_size: usize,
}

#[derive(Debug, Deserialize)]
pub struct StartAgentRequest {
    pub master_password: Option<String>,
}

/// Identity creation request
#[derive(Debug, Deserialize)]
pub struct CreateIdentityRequest {
    pub name: String,
    pub identity_type: String,
    pub description: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
}

/// Identity update request
#[derive(Debug, Deserialize)]
pub struct UpdateIdentityRequest {
    pub id: String,
    pub name: String,
    pub identity_type: String,
    pub description: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// Credential creation request
#[derive(Debug, Deserialize)]
pub struct CreateCredentialRequest {
    pub identity_id: String,
    pub name: String,
    pub credential_type: String,
    pub security_level: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub credential_data: CredentialDataRequest,
}

/// Credential metadata edit request (1Password-aligned: editing does not
/// change the item type; the payload goes through update_credential_data
/// separately)
#[derive(Debug, Deserialize)]
pub struct UpdateCredentialRequest {
    pub id: String,
    pub name: String,
    pub security_level: Option<String>,
    pub url: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// Credential payload edit request (sensitive: re-seals under the original
/// item key + sensitive-op gating)
#[derive(Debug, Deserialize)]
pub struct UpdateCredentialDataRequest {
    pub credential_id: String,
    pub credential_data: CredentialDataRequest,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum CredentialDataRequest {
    Password {
        password: String,
        email: Option<String>,
        security_questions: Vec<SecurityQuestionRequest>,
    },
    CryptoWallet {
        wallet_type: String,
        mnemonic_phrase: Option<String>,
        private_key: Option<String>,
        public_key: String,
        address: String,
        network: String,
        bip39_passphrase: Option<String>,
    },
    SshKey {
        private_key: String,
        public_key: String,
        key_type: String,
        passphrase: Option<String>,
    },
    ApiKey {
        api_key: String,
        api_secret: Option<String>,
        token: Option<String>,
        permissions: Vec<String>,
        expires_at: Option<String>,
    },
    TwoFactor {
        secret_key: String,
        issuer: String,
        account_name: String,
        algorithm: String,
        digits: u8,
        period: u32,
        /// HOTP (RFC 4226) counter-based entry; the default (older frontends) is
        /// time-based TOTP.
        #[serde(default)]
        hotp: Option<bool>,
        #[serde(default)]
        initial_counter: Option<u64>,
    },
    GameToken {
        provider: String,
        secret_key: String,
        issuer: String,
        account_name: String,
        url: Option<String>,
    },
    SecureNote {
        note: String,
    },
    Identity {
        first_name: String,
        last_name: String,
        username: Option<String>,
        email: Option<String>,
        phone: Option<String>,
        birthday: Option<String>,
        address: Option<String>,
        id_number: Option<String>,
        passport_number: Option<String>,
        driver_license: Option<String>,
        tax_id: Option<String>,
        organization: Option<String>,
        job_title: Option<String>,
    },
    SoftwareLicense {
        license_key: String,
        version: Option<String>,
        publisher: Option<String>,
        purchase_date: Option<String>,
        order_number: Option<String>,
        support_email: Option<String>,
        download_url: Option<String>,
        seats: Option<u32>,
        valid_until: Option<String>,
    },
    Raw {
        data: Vec<u8>,
    },
}

#[derive(Debug, Deserialize)]
pub struct SecurityQuestionRequest {
    pub question: String,
    pub answer: String,
}

#[derive(Debug, Serialize)]
pub struct SshAgentStatus {
    pub running: bool,
    pub socket_path: Option<String>,
    pub pid: Option<u32>,
    pub key_count: Option<usize>,
    pub state_dir: String,
}

#[derive(Debug, Serialize)]
pub struct SshKeySummary {
    pub id: String,
    pub identity_id: String,
    pub identity_name: String,
    pub name: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Display only: wire-format algorithm (`ssh-ed25519`, etc.); null when the
    /// data cannot be obtained
    pub ssh_algorithm: Option<String>,
    /// Display only: SHA256 fingerprint (`SHA256:…`), using the same
    /// convention as the import/generation confirmation
    pub fingerprint: Option<String>,
    /// Display only: bit count / curve label (Ed25519→`256`, RSA→`4096`,
    /// ECDSA→`P-256`); null for containers where this does not apply, such
    /// as certificates
    pub key_size: Option<String>,
    /// Full public key line, for one-click copy into authorized_keys / GitHub
    pub public_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TotpCodeResponse {
    pub code: String,
    pub remaining_seconds: u32,
    pub period: u32,
    pub digits: u8,
    pub algorithm: String,
    pub issuer: String,
    pub account_name: String,
}

// Wallet types for Tauri commands

impl CredentialDataRequest {
    pub fn to_credential_data(&self) -> CredentialData {
        match self {
            CredentialDataRequest::Password {
                password,
                email,
                security_questions,
            } => CredentialData::Password(PasswordCredentialData {
                password: password.clone(),
                email: email.clone(),
                security_questions: security_questions
                    .iter()
                    .map(|q| SecurityQuestion {
                        question: q.question.clone(),
                        answer: q.answer.clone(),
                    })
                    .collect(),
            }),
            CredentialDataRequest::CryptoWallet {
                wallet_type,
                mnemonic_phrase,
                private_key,
                public_key,
                address,
                network,
                bip39_passphrase,
            } => CredentialData::CryptoWallet(CryptoWalletData {
                wallet_type: wallet_type.clone(),
                mnemonic_phrase: mnemonic_phrase.clone(),
                private_key: private_key.clone(),
                public_key: public_key.clone(),
                address: address.clone(),
                network: network.clone(),
                bip39_passphrase: bip39_passphrase.clone(),
                // Item-level standalone passwords are set through the separate
                // wallet_set_item_password command (a second hardening step
                // after creation); the create request does not carry them
                item_password_hash: None,
                item_password_hint: None,
            }),
            CredentialDataRequest::SshKey {
                private_key,
                public_key,
                key_type,
                passphrase,
            } => CredentialData::SshKey(SshKeyData {
                private_key: private_key.clone(),
                public_key: public_key.clone(),
                key_type: key_type.clone(),
                passphrase: passphrase.clone(),
            }),
            CredentialDataRequest::ApiKey {
                api_key,
                api_secret,
                token,
                permissions,
                expires_at,
            } => CredentialData::ApiKey(ApiKeyData {
                api_key: api_key.clone(),
                api_secret: api_secret.clone(),
                token: token.clone(),
                permissions: permissions.clone(),
                expires_at: expires_at
                    .as_ref()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&chrono::Utc)),
            }),
            CredentialDataRequest::TwoFactor {
                secret_key,
                issuer,
                account_name,
                algorithm,
                digits,
                hotp,
                initial_counter,
                period,
            } => CredentialData::TwoFactor(TwoFactorData {
                secret_key: secret_key.clone(),
                issuer: issuer.clone(),
                account_name: account_name.clone(),
                algorithm: algorithm.clone(),
                digits: *digits,
                period: *period,
                hotp: *hotp,
                initial_counter: *initial_counter,
            }),
            CredentialDataRequest::GameToken {
                provider,
                secret_key,
                issuer,
                account_name,
                url,
            } => CredentialData::GameToken(GameTokenData {
                provider: provider.clone(),
                secret_key: secret_key.clone(),
                issuer: issuer.clone(),
                account_name: account_name.clone(),
                url: url.clone(),
                identity_secret: None,
                device_id: None,
            }),
            CredentialDataRequest::SecureNote { note } => {
                CredentialData::SecureNote(SecureNoteData { note: note.clone() })
            }
            CredentialDataRequest::Identity {
                first_name,
                last_name,
                username,
                email,
                phone,
                birthday,
                address,
                id_number,
                passport_number,
                driver_license,
                tax_id,
                organization,
                job_title,
            } => CredentialData::Identity(IdentityData {
                first_name: first_name.clone(),
                last_name: last_name.clone(),
                username: username.clone(),
                email: email.clone(),
                phone: phone.clone(),
                birthday: birthday.clone(),
                address: address.clone(),
                id_number: id_number.clone(),
                passport_number: passport_number.clone(),
                driver_license: driver_license.clone(),
                tax_id: tax_id.clone(),
                organization: organization.clone(),
                job_title: job_title.clone(),
            }),
            CredentialDataRequest::SoftwareLicense {
                license_key,
                version,
                publisher,
                purchase_date,
                order_number,
                support_email,
                download_url,
                seats,
                valid_until,
            } => CredentialData::SoftwareLicense(SoftwareLicenseData {
                license_key: license_key.clone(),
                version: version.clone(),
                publisher: publisher.clone(),
                purchase_date: purchase_date.clone(),
                order_number: order_number.clone(),
                support_email: support_email.clone(),
                download_url: download_url.clone(),
                seats: *seats,
                valid_until: valid_until.clone(),
            }),
            CredentialDataRequest::Raw { data } => CredentialData::Raw(data.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit queries
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RevealSecretRequest {
    pub credential_id: String,
    /// "password" | "security_questions" | "ssh_private_key" | "ssh_passphrase" |
    /// "api_key" | "api_secret" | "token" | "wallet_private_key" |
    /// "wallet_mnemonic" | "raw_data"
    pub field: String,
    /// Wallet item-level standalone password (optional): when the entry has
    /// item_password_hash set, its seed material must be carried on every
    /// reveal; the backend returns the plaintext only after an Argon2id match
    #[serde(default)]
    pub item_password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SecretRevealResponse {
    pub field: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct ReauthRequest {
    pub master_password: String,
}

/// Quick Access floating window's "open in Persona": the two ids for the
/// cross-window jump (UUID form; the backend re-validates — frontend
/// validation is only early feedback)
#[derive(Debug, Deserialize)]
pub struct QuickAccessOpenCredentialRequest {
    pub identity_id: String,
    pub credential_id: String,
}

// ---------------------------------------------------------------------------
// Identity export
// ---------------------------------------------------------------------------
