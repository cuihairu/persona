//! Sync-group passcode pairing (cross-device sync S1, `docs/sync-group-mode.md`
//! section 2.1-2).
//!
//! Accountless join: the inviting side issues a short-lived passcode, the
//! joining side types the same code, a PAKE exchange produces a strong shared
//! key (pairing key), and the group key — AEAD-wrapped with it — is delivered
//! via the relay. Neither the short code nor the group key ever travels the
//! relay line (the relay only sees SRP public messages and ciphertext
//! envelopes; it stays zero-knowledge).
//!
//! Protocol (SRP-6a primitives reused from [`crate::auth::srp`], pinned to
//! RFC 5054 test vectors); host = inviting side (in the group, holds the group
//! key), guest = joining side, relay = accountless mailbox:
//!
//! 1. [`PairingHost::new_invite`] → `(host, invite{code, salt})`; code shown
//! 2. [`PairingGuest::start`] (code typed in) → `client_public` to the host via
//!    the relay
//! 3. [`PairingHost::accept_join`] → `server_public` back to the guest via the
//!    relay; both sides derive a 6-digit short fingerprint for display and
//!    human comparison (MITM defense)
//! 4. [`PairingGuest::finish`] → `client_proof` (M1) to the host via the relay
//!    (submitted only after the comparison passes)
//! 5. [`PairingHost::complete`] → validates M1, releases `{server_proof(M2),
//!    wrapped_group_key}`; M2 is delivered only after M1 verifies
//! 6. [`PairingGuest::accept_handoff`] → validates M2, extracts the group key,
//!    join complete
//!
//! Security semantics:
//! - **The short code is not a key**: it is first run through Argon2id (its own
//!   domain prefix, a distinct protocol domain from local unlock/backup/login
//!   SRP), and only the derived value enters SRP's `x`;
//! - **MITM defense**: a middleman without the short code cannot derive the same
//!   pairing key; a short-fingerprint mismatch is caught by the human
//!   comparison, and M1/M2 mutual proofs back this up;
//! - **One-way delivery**: `wrapped_group_key` can only be opened with the
//!   pairing key, so the relay holding ciphertext gains nothing;
//!   `complete`/`accept_handoff` are both single-use (they consume the
//!   handshake state).
//! - TTL / one session / attempt caps are the relay layer's job (see server
//!   `/api/v1/pairing/*`); this module is pure crypto logic with no IO.
//!
//! # Module layout
//!
//! Parameters and code/KDF/fingerprint/group-key sealing live in [`crypto`],
//! the host side in [`host`], the guest side in [`guest`], wire messages and
//! the invite link in [`message`], and the relay client in [`relay`].

mod crypto;
mod guest;
mod host;
mod message;
#[cfg(feature = "remote-auth")]
pub mod relay;

pub use crypto::*;
pub use guest::*;
pub use host::*;
pub use message::*;

#[cfg(test)]
mod tests;
