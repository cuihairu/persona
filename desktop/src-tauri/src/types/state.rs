//! `AppState` and `PairingSession`: Tauri global state and the sync-group
//! pairing session (in-memory state).

use persona_core::*;
use std::collections::HashMap;
use std::sync::Arc;
use tauri::async_runtime::JoinHandle;
use tokio::sync::Mutex;

/// Application state that holds the Persona service
///
/// `service` is wrapped in an `Arc`: the auto-lock callback triggers the
/// lock from a separate task, which needs to hold the same reference without
/// going through Tauri `State`.
pub struct AppState {
    pub service: Arc<Mutex<Option<PersonaService>>>,
    pub db_path: Mutex<Option<String>>,
    pub agent_handle: Mutex<Option<JoinHandle<()>>>,
    /// The auto-lock callback is registered only once (guards against
    /// duplicates across repeated init_service calls)
    pub auto_lock_registered: std::sync::atomic::AtomicBool,
    /// The passkey approval server has already been started this session
    /// (idempotence marker behind the workspace switch gate)
    pub passkey_server_started: std::sync::atomic::AtomicBool,
    /// Shutdown channel for the passkey approval server (filled by
    /// maybe_start, consumed and sent when the flag is turned off;
    /// None = not started or already shut down this session)
    pub passkey_server_shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// Pending SSH signing approvals (request_id -> oneshot), written by
    /// DesktopApprovalHandler and taken out by the ssh_approval_respond
    /// command
    pub ssh_approvals: Arc<std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>>,
    /// Pending bridge passkey approvals (request_id -> oneshot), written by
    /// the passkey_bridge server and taken out by the
    /// passkey_approval_respond command
    pub passkey_approvals:
        Arc<std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>>,
    /// Sync uploader for audit events (driven by settings.sync;
    /// None = not enabled). The slot is the source of truth: on re-mount,
    /// stop the old one before swapping in the new one, preventing two
    /// tasks. Note the fully-qualified path here — `tauri::Emitter` (the
    /// event emit trait) takes the `Emitter` name.
    pub sync_emitter: Mutex<Option<persona_core::events::Emitter>>,
    /// Field-level encrypted storage for the sync token (production = OS
    /// keyring, tests = in-memory fake). The `server_token` in the vault
    /// settings JSON is always an empty-string placeholder; the real value
    /// lives only here.
    pub token_store: Arc<dyn crate::token_store::TokenStore>,
    /// OS-level biometric provider (Touch ID / Windows Hello / polkit).
    /// The unlock-screen ceremony has no live PersonaService, so the
    /// provider is parked here; init_service injects it into PersonaService
    /// after building the service (the same instance as the SSH agent's
    /// require_biometric policy).
    pub biometric_provider: Arc<dyn BiometricProvider>,
    /// Hardware-bound key wrapper (the `biometric_wrap` module trait).
    /// Production wiring is chosen per platform: with
    /// PERSONA_BIOMETRIC_SE_SPIKE=1 on macOS this is the Secure Enclave
    /// route B' implementation; on other platforms / by default it is a
    /// gate-only stub (capability OsGateOnly -> enable always goes through
    /// gate-layer password custody, same behavior as earlier versions).
    pub biometric_wrapper: Arc<dyn persona_core::BiometricKeyWrapper>,
    /// Keyring storage for the biometric-custodied master password (service
    /// "persona-biometric", key = vault db_path). Whether the entry exists
    /// says whether biometric unlock is enabled (single source of truth;
    /// settings stores no switch — after copying the vault files to another
    /// machine the keyring has no entry, so the feature naturally reverts to
    /// disabled).
    pub biometric_store: Arc<dyn crate::token_store::TokenStore>,
    /// Keyring storage for the hardware-bound wrapper blob (service
    /// "persona-biometric-wrap"). Like biometric_store it stores ciphertext
    /// only: the blob is the master key wrapped by platform hardware keys,
    /// unreadable even to a process reading it as the same user.
    pub biometric_wrap_store: Arc<dyn crate::token_store::TokenStore>,
    /// Connect local-automation listener handle (port + shutdown channel);
    /// None = not started (DR-4 default off = no listener created). The slot
    /// is the source of truth; start/stop swap slots to avoid two listeners.
    pub connect_server: Mutex<Option<crate::connect_server::ConnectServerHandle>>,
    /// E2EE sync device identity storage (production = OS keyring service
    /// `persona-device`, tests = in-memory fake). Value =
    /// `DeviceIdentity::to_stored_json`, key as in token_store = vault
    /// db_path. Whether the entry exists says whether this vault has joined
    /// sync (single source of truth; settings stores no switch).
    pub device_store: Arc<dyn crate::token_store::TokenStore>,
    /// Keyring storage for the account-domain bearer (service
    /// `persona-account`, key as in token_store = vault db_path). Written
    /// after `account_srp_verify` / `account_create_session` succeeds and
    /// cleared on self-revocation by `account_revoke_session`; the
    /// bearer-gated account commands resolve it from here (fail-closed).
    pub account_token_store: Arc<dyn crate::token_store::TokenStore>,
    /// In-process runtime state of the Quick Access global hotkey (actual
    /// grab result + failure reason). The persisted truth for the binding
    /// and switch lives in workspace settings; this field only reflects
    /// "whether the OS grab succeeded in this process" — see the
    /// `quick_access` module notes. Uses a std Mutex (like the
    /// ssh_approvals slot): only field reads/writes inside the lock, never
    /// held across await.
    pub quick_access: std::sync::Mutex<crate::quick_access::QuickAccessRuntime>,
    /// Desktop fill injection target (FEATURE_GAP_ANALYSIS #12): the
    /// foreground window snapshot (`desktop_fill::FillTarget`) captured when
    /// the hotkey summons the search popup. None = not captured yet / target
    /// stale / platform unsupported. std Mutex: only snapshot reads/writes
    /// inside the lock, never held across await.
    pub fill_target: std::sync::Mutex<Option<crate::desktop_fill::FillTarget>>,
    /// In-flight sync-group pairing sessions (session_id -> session state).
    /// The host code-issue side and the guest code-entry side each store one;
    /// removed on completion/cancel. The dynamic-code derived value and the
    /// SRP private shares live only here (in memory, never persisted) — see
    /// the `core/src/sync/pairing.rs` module notes. Only take/put inside the
    /// lock, never held across await (the network waits in drive/join all
    /// happen outside the lock).
    pub pairing_sessions: Arc<std::sync::Mutex<HashMap<String, crate::types::PairingSession>>>,
    /// Keyring storage for the sync group key (service
    /// `persona-sync-group`, key = vault db_path, value = hex). Whether the
    /// entry exists says whether this vault has joined the sync group
    /// (single source of truth); written when pairing completes and read by
    /// the S2 command flow.
    pub sync_group_store: Arc<dyn crate::token_store::TokenStore>,
}

/// Sync-group pairing session (host code-issue / guest code-entry roles,
/// in-memory state).
pub enum PairingSession {
    /// Invite side: the dynamic-code handshake in place + the group key
    /// awaiting delivery (landed in sync_group_store on completion).
    /// GroupKey zeroes its memory (Drop/ZeroizeOnDrop).
    Host {
        host: persona_core::sync::pairing::PairingHost,
        group_key: persona_core::sync::keys::GroupKey,
        relay_url: String,
    },
    /// Join side: held between join_begin and join_confirm (confirm after the
    /// fingerprint comparison passes).
    Guest {
        guest: persona_core::sync::pairing::PairingGuest,
        relay_url: String,
    },
}
