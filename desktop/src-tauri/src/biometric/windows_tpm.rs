//! Windows: Microsoft Passport Key Storage Provider (TPM-backed hardware
//! wrapping) — the preferred route of `docs/biometric-unlock-design.md` §6.
//!
//! **Spike-gated**: this module is wired in by [`super::key_wrapper`] only when
//! the `PERSONA_BIOMETRIC_TPM_SPIKE=1` env var is set (the `biometric_tpm_spike`
//! command probes each item on real hardware and reports HRESULTs). The
//! production unlock path does not include this module by default — the actual
//! behavior of Passport KSP (whether the UI policy really prompts Hello on every
//! private-key use, silent finalize semantics, behavior after a fingerprint is
//! deleted) can only be verified on real hardware, and the default is not
//! switched until then.
//!
//! Mechanism: NCrypt opens `MS_KEY_STORAGE_PROVIDER` (Passport KSP, where the
//! key material is TPM-protected and non-exportable), creates a 2048-bit RSA
//! user key under it, with three properties pinned:
//! - `NCRYPT_KEY_USAGE_PROPERTY = NCRYPT_ALLOW_DECRYPT_FLAG` — only the
//!   "decrypt" direction of the private key (i.e. wrap/unwrap) is enabled; no
//!   signing rights;
//! - `NCRYPT_UI_POLICY_PROPERTY = NCRYPT_UI_PROTECT_KEY_FLAG`, **persisted with
//!   `NCRYPT_PERSIST_FLAG`** — every use of the private key must pass a Windows
//!   Hello user verification before the TPM releases it. Without persistence the
//!   policy only lives in this process, and after a restart unwrapping no longer
//!   prompts Hello (a silent security downgrade; must be pinned);
//! - `NCRYPT_LENGTH_PROPERTY = 2048`.
//!
//! Wrap = `NCryptEncrypt` (RSA public-key direction, **no prompt**); unwrap =
//! `NCryptDecrypt` (private-key direction, **Hello prompts here**). Like the
//! macOS route B', this is the `HardwareBound` tier from design doc §1: the
//! secret lives inside the hardware private key, and the keyring only holds
//! ciphertext that cannot be opened.
//!
//! ## Capability gap vs macOS B' (honest boundary, do not blur in docs)
//!
//! **Enrollment-set drift (T2) has no platform-level enforcement on Windows**:
//! Apple's `biometryCurrentSet` permanently invalidates old SE keys after a
//! fingerprint change; Windows has no equivalent API — `NCRYPT_UI_PROTECT_KEY_FLAG`
//! enforces "user verification on every use", and the verifier being a new
//! fingerprint does **not** invalidate the old key. Therefore
//! [`TpmKeyWrapper::enrollment_fingerprint`] can only return a fixed placeholder
//! (same shape as the macOS placeholder, but on macOS "the platform already
//! enforces it and this is just a second line of defense" whereas on Windows
//! "the platform does nothing and there is no second line").
//!
//! Residual risk: an attacker with local login state who can complete one
//! Windows Hello verification (any fingerprint/PIN already enrolled) can unwrap
//! old blobs — the anti-coercion property of "change fingerprint" does not hold
//! on Windows. Mitigation is the master password fallback plus the fact that the
//! wrap blob in the keyring is only ciphertext (a same-user process reading it
//! cannot open it unless it can pass Hello).
//!
//! ## Verification status
//!
//! **Compilation** is gated by the Linux cross-check (`x86_64-pc-windows-msvc`
//! with empty `CC`/`llvm-ar` stubs, same technique as design doc §5.3) and the
//! Windows job of `desktop-build`; **runtime** behavior is judged by real-hardware
//! spike output (the §6.1 probes have not been run, conclusions pending
//! backfill). This repo has no Windows hardware.

use windows::core::{w, HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    ERROR_NOT_FOUND, NTE_BAD_KEYSET, NTE_USER_CANCELLED, SCARD_W_CANCELLED_BY_USER,
};
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey,
    NCryptFreeObject, NCryptIsAlgSupported, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty, CERT_KEY_SPEC, MS_KEY_STORAGE_PROVIDER, NCRYPT_ALLOW_DECRYPT_FLAG,
    NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY,
    NCRYPT_LENGTH_PROPERTY, NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PERSIST_FLAG,
    NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM, NCRYPT_SILENT_FLAG, NCRYPT_UI_POLICY_PROPERTY,
    NCRYPT_UI_PROTECT_KEY_FLAG,
};
use zeroize::Zeroizing;

use persona_core::{
    BiometricKeyWrapper, BiometricWrapCapability, BiometricWrapError, WrapPlatform,
};

/// Key name inside the KSP (user-level; a key with the same name is unique under
/// the local user profile)
const KEY_NAME: PCWSTR = w!("persona.vault-wrap.v1");

/// 2048-bit RSA + PKCS#1 v1.5: the plaintext limit is 245 bytes, and the 32-byte
/// vault master key is far below it; we do not go up to 3072/4096 because of TPM
/// side latency (unwrap is a user-perceivable path)
const KEY_BITS: u32 = 2048;

/// RAII wrapper for NCrypt handles (provider and key handles share the same
/// release function)
struct OwnedHandle(NCRYPT_HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // Nowhere to propagate from drop: a failed release is simply dropped
        // (one leaked entry in the handle table, same lifetime as the process,
        // acceptable); no panic — panicking on a destructor path would abort
        // SAFETY: the handle came from a successful NCrypt call, and this RAII
        // releases it exactly once
        let _ = unsafe { NCryptFreeObject(self.0) };
    }
}

/// NCrypt error → wrap-layer error. If the user hits cancel in the Hello dialog
/// it maps to `UserCancelled` (silently back to the unlock screen); everything
/// else becomes `Platform` verbatim with the HRESULT (the host uses that to
/// automatically delete the blob and fall back to the master password, see
/// design doc §3.4).
fn map_ncrypt_err(err: windows::core::Error, step: &str) -> BiometricWrapError {
    let code = err.code();
    // For Passport KSP the cancellation is NTE_USER_CANCELLED via the WinRT layer
    // and SCARD_W_CANCELLED_BY_USER via the smart-card layer — accept both
    if code == NTE_USER_CANCELLED || code == SCARD_W_CANCELLED_BY_USER {
        return BiometricWrapError::UserCancelled;
    }
    BiometricWrapError::Platform(format!(
        "{step}: hr=0x{:08x} {}",
        code.0 as u32,
        err.message()
    ))
}

/// Open the Passport KSP
fn open_provider() -> Result<OwnedHandle, BiometricWrapError> {
    let mut provider = NCRYPT_PROV_HANDLE(0);
    // SAFETY: the out pointer is owned by this function; the provider name is a
    // framework constant
    unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) }
        .map_err(|e| map_ncrypt_err(e, "NCryptOpenStorageProvider (MSKSP)"))?;
    Ok(OwnedHandle(NCRYPT_HANDLE(provider.0)))
}

/// Whether the KSP supports the RSA private-key decrypt direction (the only
/// algorithm capability the wrap layer needs)
fn provider_supports_rsa(provider: &OwnedHandle) -> bool {
    // NCryptIsAlgSupported expresses "not supported" with a failure code; here
    // we only want a boolean
    // SAFETY: the provider handle is valid; the algorithm identifier is a
    // framework constant
    unsafe {
        NCryptIsAlgSupported(
            NCRYPT_PROV_HANDLE(provider.0 .0),
            NCRYPT_RSA_ALGORITHM,
            NCRYPT_ALLOW_DECRYPT_FLAG,
        )
    }
    .is_ok()
}

/// The two HRESULTs meaning "key does not exist": MSKSP usually returns
/// `NTE_BAD_KEYSET`, while some system versions/backends return
/// `ERROR_NOT_FOUND`(1168). Both mean "missing" rather than "broken" — only
/// these two permit automatic key re-creation; all other errors are propagated
/// (do not mask a real failure).
fn is_key_absent(code: HRESULT) -> bool {
    code == NTE_BAD_KEYSET || code == HRESULT::from_win32(ERROR_NOT_FOUND.0)
}

/// Open an existing wrap key; returns `Ok(None)` if absent
fn open_key(provider: &OwnedHandle) -> Result<Option<OwnedHandle>, BiometricWrapError> {
    let mut key = NCRYPT_KEY_HANDLE(0);
    // SAFETY: the provider handle is valid; the out pointer is owned by this
    // function; the key name is a constant
    match unsafe {
        NCryptOpenKey(
            NCRYPT_PROV_HANDLE(provider.0 .0),
            &mut key,
            KEY_NAME,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    } {
        Ok(()) => Ok(Some(OwnedHandle(NCRYPT_HANDLE(key.0)))),
        Err(e) if is_key_absent(e.code()) => Ok(None),
        Err(e) => Err(map_ncrypt_err(e, "NCryptOpenKey")),
    }
}

fn set_u32_property(
    key: &OwnedHandle,
    name: PCWSTR,
    value: u32,
    flags: NCRYPT_FLAGS,
) -> Result<(), BiometricWrapError> {
    // SAFETY: the handle is valid; value is 4 bytes on this function's stack,
    // read synchronously by NCryptSetProperty and not stored by pointer
    unsafe { NCryptSetProperty(NCRYPT_HANDLE(key.0 .0), name, &value.to_ne_bytes(), flags) }
        .map_err(|e| map_ncrypt_err(e, "NCryptSetProperty"))
}

/// Create the wrap key: RSA-2048 / decrypt-only usage / Hello on every use
/// (policy persisted)
///
/// `NCRYPT_OVERWRITE_KEY_FLAG`: on rebuild, overwrite a same-name leftover
/// (the user cleared Passport keys, or a previous enable failed before finalize
/// and left a half-state), so rebuilding does not get permanently stuck on
/// "opening yields a bad key".
fn create_key(provider: &OwnedHandle) -> Result<OwnedHandle, BiometricWrapError> {
    let mut key = NCRYPT_KEY_HANDLE(0);
    // SAFETY: the provider handle is valid; the out pointer is owned by this
    // function; the algorithm/key names are constants
    unsafe {
        NCryptCreatePersistedKey(
            NCRYPT_PROV_HANDLE(provider.0 .0),
            &mut key,
            NCRYPT_RSA_ALGORITHM,
            KEY_NAME,
            CERT_KEY_SPEC(0),
            NCRYPT_OVERWRITE_KEY_FLAG,
        )
    }
    .map_err(|e| map_ncrypt_err(e, "NCryptCreatePersistedKey"))?;
    let key = OwnedHandle(NCRYPT_HANDLE(key.0));

    set_u32_property(&key, NCRYPT_LENGTH_PROPERTY, KEY_BITS, NCRYPT_FLAGS(0))?;
    set_u32_property(
        &key,
        NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_ALLOW_DECRYPT_FLAG,
        NCRYPT_FLAGS(0),
    )?;
    // the policy needs NCRYPT_PERSIST_FLAG to be written to disk with the key
    // (see the module header)
    set_u32_property(
        &key,
        NCRYPT_UI_POLICY_PROPERTY,
        NCRYPT_UI_PROTECT_KEY_FLAG,
        NCRYPT_PERSIST_FLAG,
    )?;

    // Silent finalize: the previous step on the enable path (step 2 of
    // biometric_enable in commands.rs) already went through the Hello ceremony,
    // so key creation does not pop a second dialog
    // SAFETY: the handle is valid; the handle remains legal after finalize
    unsafe { NCryptFinalizeKey(NCRYPT_KEY_HANDLE(key.0 .0), NCRYPT_SILENT_FLAG) }
        .map_err(|e| map_ncrypt_err(e, "NCryptFinalizeKey"))?;
    Ok(key)
}

/// Find or create the wrap key (used only on the enable/wrap path — unwrap goes
/// through open_key_only)
fn generate_or_find_key() -> Result<OwnedHandle, BiometricWrapError> {
    let provider = open_provider()?;
    if let Some(key) = open_key(&provider)? {
        return Ok(key);
    }
    create_key(&provider)
}

/// Exclusive to the unwrap path: **only** opens, and returns `WrapInvalid` if
/// absent.
///
/// The difference from macOS B' is deliberate: over there unwrap also goes
/// through generate_or_find, so a missing key first creates a new key and then
/// fails on ECIES — leaving an orphan key nobody uses, and disguising the real
/// failure ("the blob came from another machine / the user cleared the Passport
/// keys") as a decryption error. The host's handling of `WrapInvalid` is to
/// delete the blob and fall back to the master password (design doc §3.4),
/// which is exactly the right semantics.
fn open_key_only() -> Result<OwnedHandle, BiometricWrapError> {
    let provider = open_provider()?;
    open_key(&provider)?.ok_or(BiometricWrapError::WrapInvalid)
}

/// RSA public-key direction wrap (no user interaction)
fn rsa_wrap(key: &OwnedHandle, plaintext: &[u8]) -> Result<Vec<u8>, BiometricWrapError> {
    let mut len = 0u32;
    // SAFETY: the handle is valid; per the NCrypt convention, a size query
    // passes pboutput=None to get the length
    unsafe {
        NCryptEncrypt(
            NCRYPT_KEY_HANDLE(key.0 .0),
            Some(plaintext),
            None,
            None,
            &mut len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    }
    .map_err(|e| map_ncrypt_err(e, "NCryptEncrypt (size)"))?;
    let mut out = vec![0u8; len as usize];
    // SAFETY: out is exactly the length reported by the previous step
    unsafe {
        NCryptEncrypt(
            NCRYPT_KEY_HANDLE(key.0 .0),
            Some(plaintext),
            None,
            Some(&mut out),
            &mut len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    }
    .map_err(|e| map_ncrypt_err(e, "NCryptEncrypt"))?;
    out.truncate(len as usize);
    Ok(out)
}

/// RSA private-key direction unwrap (Windows Hello is prompted here by the
/// TPM/KSP)
fn rsa_unwrap(key: &OwnedHandle, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, BiometricWrapError> {
    let mut len = 0u32;
    // SAFETY: the handle is valid; a size query passes pboutput=None
    unsafe {
        NCryptDecrypt(
            NCRYPT_KEY_HANDLE(key.0 .0),
            Some(payload),
            None,
            None,
            &mut len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    }
    .map_err(|e| map_ncrypt_err(e, "NCryptDecrypt (size)"))?;
    // The plaintext buffer stays Zeroizing throughout: what is decrypted is the
    // vault master key itself
    let mut plain = Zeroizing::new(vec![0u8; len as usize]);
    // SAFETY: the buffer is exactly the length reported by the previous step
    unsafe {
        NCryptDecrypt(
            NCRYPT_KEY_HANDLE(key.0 .0),
            Some(payload),
            None,
            Some(plain.as_mut_slice()),
            &mut len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    }
    .map_err(|e| map_ncrypt_err(e, "NCryptDecrypt"))?;
    plain.truncate(len as usize);
    Ok(plain)
}

/// Delete the wrap key in the KSP (idempotent: absence also counts as success)
fn delete_tpm_key() -> Result<(), BiometricWrapError> {
    let provider = open_provider()?;
    match open_key(&provider)? {
        Some(key) => {
            let handle = NCRYPT_KEY_HANDLE(key.0 .0);
            // SAFETY: the handle comes from NCryptOpenKey
            let result = unsafe { NCryptDeleteKey(handle, 0) }
                .map_err(|e| map_ncrypt_err(e, "NCryptDeleteKey"));
            // `NCryptDeleteKey` disposes of the handle itself (after success it is
            // certainly freed; on failure MSDN does not promise whether the
            // handle still belongs to the caller). Here we **always** drop the
            // RAII release right: the cost of guessing the wrong direction is
            // asymmetric — releasing twice is UB (handle-table corruption,
            // possibly turning into a wild pointer elsewhere), whereas skipping
            // one release merely leaks a handle, and only on the delete-failure
            // path that we are going to propagate anyway.
            std::mem::forget(key);
            result
        }
        None => Ok(()),
    }
}

pub fn spike_enabled() -> bool {
    std::env::var_os("PERSONA_BIOMETRIC_TPM_SPIKE").is_some_and(|v| v == "1")
}

/// Spike-gated assembly entry point (called by `biometric::key_wrapper`)
pub fn spike_wrapper_if_enabled() -> Option<TpmKeyWrapper> {
    if spike_enabled() {
        Some(TpmKeyWrapper)
    } else {
        None
    }
}

/// Windows Hello availability (gate-layer probe; the wrap layer's user
/// verification is actually performed by the KSP itself, this only makes the
/// "Hello is installed on this machine" pre-check)
fn hello_available() -> bool {
    super::windows_hello::available()
}

/// Hardware wrap wrapper for Microsoft Passport KSP
pub struct TpmKeyWrapper;

impl BiometricKeyWrapper for TpmKeyWrapper {
    fn capability(&self) -> BiometricWrapCapability {
        BiometricWrapCapability::HardwareBound
    }

    fn is_available(&self) -> bool {
        // Missing any one of the three makes it unavailable (fail-closed):
        // KSP won't open, algorithm unsupported, or no usable Windows Hello
        // on this machine
        match open_provider() {
            Ok(provider) => provider_supports_rsa(&provider) && hello_available(),
            Err(_) => false,
        }
    }

    fn platform(&self) -> WrapPlatform {
        WrapPlatform::WindowsTpm
    }

    fn enrollment_fingerprint(&self) -> Result<[u8; 32], BiometricWrapError> {
        // The platform layer has no notion of a "biometric enrollment-set
        // fingerprint" (see the module header, "capability gap vs macOS B'"):
        // changing a fingerprint does not invalidate old wraps, so the core's
        // second comparison can only be a placeholder here. Returning all zeros
        // — we do not fabricate enrollment-set state; better to let this check
        // fail than to report a value that drifts with the environment.
        Ok([0u8; 32])
    }

    fn wrap_payload(
        &self,
        master_key: &[u8; 32],
        _prompt: &str,
    ) -> Result<Vec<u8>, BiometricWrapError> {
        let key = generate_or_find_key()?;
        rsa_wrap(&key, master_key)
    }

    fn unwrap_payload(
        &self,
        payload: &[u8],
        prompt: &str,
    ) -> Result<Zeroizing<[u8; 32]>, BiometricWrapError> {
        // Dialog wording is governed by the KSP's UI policy mechanism (the
        // NCrypt layer does not accept caller-provided text); the Rust side is
        // audit-only
        let _ = prompt;
        let key = open_key_only()?;
        let plain = rsa_unwrap(&key, payload)?;
        let arr: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| BiometricWrapError::WrapInvalid)?;
        Ok(Zeroizing::new(arr))
    }

    fn delete_wrap_payload(&self, _payload: &[u8]) -> Result<(), BiometricWrapError> {
        delete_tpm_key()
    }
}

// ---------------------------------------------------------------------------
// spike probes (consumed by the `biometric_tpm_spike` command)
// ---------------------------------------------------------------------------

/// Spike-specific probe output: per-step HRESULTs/verdicts, to be pasted back
/// into design doc §6.1 after running on real hardware
pub struct SpikeStep {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// Run all spike probes (corresponds to the table in design doc §6.1).
///
/// "Unwrap after deleting one fingerprint" and "run once more after a restart
/// to check the key is still there" are two **manual** controls: after this
/// function completes, perform the operation and run it again — probe 5b must
/// fail and probe 6 must still report found to count as a pass.
pub fn run_spike() -> Vec<SpikeStep> {
    let mut steps = Vec::new();

    // 1. Can the KSP be opened
    let provider = match open_provider() {
        Ok(p) => {
            steps.push(SpikeStep {
                name: "1. NCryptOpenStorageProvider (Microsoft Passport KSP)",
                ok: true,
                detail: "provider opened".into(),
            });
            p
        }
        Err(e) => {
            steps.push(SpikeStep {
                name: "1. NCryptOpenStorageProvider (Microsoft Passport KSP)",
                ok: false,
                detail: e.to_string(),
            });
            return steps;
        }
    };

    // 2. Algorithm capability
    let rsa_ok = provider_supports_rsa(&provider);
    steps.push(SpikeStep {
        name: "2. NCryptIsAlgSupported (RSA, NCRYPT_ALLOW_DECRYPT_FLAG)",
        ok: rsa_ok,
        detail: if rsa_ok {
            "RSA decrypt supported".into()
        } else {
            "provider cannot do RSA private-key decrypt".to_string()
        },
    });
    if !rsa_ok {
        return steps;
    }

    // 3. Windows Hello prerequisites
    let hello = hello_available();
    steps.push(SpikeStep {
        name: "3. Windows Hello availability (UserConsentVerifier)",
        ok: hello,
        detail: if hello {
            "hello available".into()
        } else {
            "UserConsentVerifier reports unavailable — no enrolled PIN/fingerprint?".to_string()
        },
    });

    // 4. Key creation (including UI policy persistence) + check right after
    let key = match generate_or_find_key() {
        Ok(k) => {
            steps.push(SpikeStep {
                name: "4. NCryptCreatePersistedKey (RSA-2048, UI policy persisted)",
                ok: true,
                detail: "created or found".into(),
            });
            k
        }
        Err(e) => {
            steps.push(SpikeStep {
                name: "4. NCryptCreatePersistedKey (RSA-2048, UI policy persisted)",
                ok: false,
                detail: e.to_string(),
            });
            return steps;
        }
    };
    steps.push(match open_key(&provider) {
        Ok(Some(_)) => SpikeStep {
            name: "4b. NCryptOpenKey after create",
            ok: true,
            detail: "key found right after creation".into(),
        },
        Ok(None) => SpikeStep {
            name: "4b. NCryptOpenKey after create",
            ok: false,
            detail: "key not found right after creation".into(),
        },
        Err(e) => SpikeStep {
            name: "4b. NCryptOpenKey after create",
            ok: false,
            detail: e.to_string(),
        },
    });

    // 5. roundtrip: wrap (public-key direction, must not prompt) -> unwrap
    // (private-key direction, must prompt Hello)
    let probe = b"persona-spike-probe";
    let ciphertext = match rsa_wrap(&key, probe) {
        Ok(c) => {
            steps.push(SpikeStep {
                name: "5a. NCryptEncrypt (public key, must not prompt)",
                ok: true,
                detail: format!("{} bytes", c.len()),
            });
            c
        }
        Err(e) => {
            steps.push(SpikeStep {
                name: "5a. NCryptEncrypt (public key, must not prompt)",
                ok: false,
                detail: e.to_string(),
            });
            return steps;
        }
    };
    steps.push(match rsa_unwrap(&key, &ciphertext) {
        Ok(plain) => {
            let ok = plain.as_slice() == probe;
            SpikeStep {
                name: "5b. NCryptDecrypt (must prompt Windows Hello)",
                ok,
                detail: if ok {
                    "roundtrip ok — confirm the Hello prompt actually appeared".into()
                } else {
                    "content mismatch".into()
                },
            }
        }
        Err(e) => SpikeStep {
            name: "5b. NCryptDecrypt (must prompt Windows Hello)",
            ok: false,
            detail: e.to_string(),
        },
    });

    // 6. Persistence: this process can re-open the existing key; full "after
    // restart" verification = terminate this process and run the spike again,
    // this step still reports found
    steps.push(match open_key(&provider) {
        Ok(Some(_)) => SpikeStep {
            name: "6. NCryptOpenKey (persistence probe)",
            ok: true,
            detail:
                "run this spike again after restarting the app to prove cross-restart persistence"
                    .into(),
        },
        Ok(None) => SpikeStep {
            name: "6. NCryptOpenKey (persistence probe)",
            ok: false,
            detail: "key disappeared within the same process".into(),
        },
        Err(e) => SpikeStep {
            name: "6. NCryptOpenKey (persistence probe)",
            ok: false,
            detail: e.to_string(),
        },
    });

    // 7. Delete idempotency: deleting twice in a row must both succeed (the
    // disable/invalidate self-heal paths share this route)
    let first = delete_tpm_key();
    let second = delete_tpm_key();
    let ok = first.is_ok() && second.is_ok();
    steps.push(SpikeStep {
        name: "7. NCryptDeleteKey (idempotent, called twice)",
        ok,
        detail: if ok {
            "deleted; second delete returned Ok (not-found is success)".into()
        } else {
            format!(
                "first={:?} second={:?}",
                first.err().map(|e| e.to_string()),
                second.err().map(|e| e.to_string())
            )
        },
    });

    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real-hardware/CI probe entry point: `cargo test --lib
    /// spike_probes_print_report -- --ignored --nocapture`. A GitHub runner's
    /// Windows VM usually has no enrolled Windows Hello / vTPM authentication
    /// state, so each step will honestly fail and log its HRESULT (the
    /// desktop-build windows job runs it precisely to record this real output
    /// and backfill design doc §6.1); probe 7 performs the deletion itself, so
    /// no persistent key is left on the runner.
    /// The assertion only guarantees "a report is produced"; manual judgement of
    /// the ok field happens on the spike output side.
    #[test]
    #[ignore = "需要真实 Windows 环境（Windows Hello / Passport KSP）；desktop-build windows job 按计划跑"]
    fn spike_probes_print_report() {
        let steps = run_spike();
        assert!(!steps.is_empty(), "spike 必须产出探针报告");
        for s in steps {
            println!(
                "SPIKE [{}] {} — {}",
                if s.ok { "PASS" } else { "FAIL" },
                s.name,
                s.detail
            );
        }
    }
}
