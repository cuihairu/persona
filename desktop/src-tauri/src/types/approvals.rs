//! SSH / passkey approval event payloads (`persona://*-approval` wire messages).

use serde::Serialize;

/// `persona://ssh-approval` event payload: one SSH signing request awaiting
/// approval
#[derive(Debug, Clone, Serialize)]
pub struct SshApprovalRequest {
    pub request_id: String,
    /// Credential UUID (not sensitive)
    pub key_id: String,
    /// Public key fingerprint (first 8 bytes of SHA256, for manual
    /// verification)
    pub fingerprint: String,
    /// Operation name (currently always "sign")
    pub operation: String,
    /// Target host (null when unknown)
    pub peer: Option<String>,
    /// Triggering reason (policy explanation)
    pub reason: String,
}

/// `persona://passkey-approval` event payload: one bridge passkey request
/// awaiting approval.
/// Contains only metadata such as origin/rp/account — clientDataJSON never
/// leaves the bridge process.
#[derive(Debug, Clone, Serialize)]
pub struct PasskeyApprovalRequest {
    pub request_id: String,
    /// Operation name taken over from the bridge wire:
    /// "passkey_create" | "passkey_assert"
    pub operation: String,
    /// Relying party for manual verification (None for assert: the rp lives
    /// on the vault item)
    pub rp_id: Option<String>,
    /// Full page origin that initiated the request
    pub origin: String,
    /// Account name at create time (for assert it is on the stored item,
    /// which the desktop has no way to know)
    pub user_name: Option<String>,
    /// UUID of the vault item the assert corresponds to
    pub item_id: Option<String>,
}

// ---- Account system (M2: the tauri proxy-layer contract for
//      persona-server /api/v1/accounts/*. Field names/shapes correspond
//      one-to-one with the account seam in desktop/src/utils/api.ts and
//      server/src/api/accounts.rs; the command side is the account_* family
//      in commands.rs)----
