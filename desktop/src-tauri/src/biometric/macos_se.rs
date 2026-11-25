//! macOS: Secure Enclave route B' — a permanent SE key plus ECIES wrapping of
//! the vault master key (`docs/biometric-unlock-design.md` §5).
//!
//! **Spike-gated**: this module is wired in by [`super::key_wrapper`] only when
//! the `PERSONA_BIOMETRIC_SE_SPIKE=1` env var is set (the `biometric_wrap_spike`
//! command probes each item on real hardware and reports OSStatus codes). The
//! production unlock path does not include this module by default — whether
//! route B' is blocked by ad-hoc signing (`errSecMissingEntitlement -34018`) can
//! only be verified on real hardware, and the default is not switched until
//! then.
//!
//! Mechanism: `SecKeyCreateRandomKey` generates a 256-bit EC key
//! (`kSecAttrTokenID SecureEnclave` + `IsPermanent: true` + AccessControl
//! `.privateKeyUsage | .biometryCurrentSet`). Wrap = ECIES encryption with the
//! public key (no prompt); unwrap = ECIES decryption with the private key — the
//! SE enforces biometrics/system password at that moment, and the private key is
//! never exported. `biometryCurrentSet` permanently invalidates old keys after
//! a fingerprint change.
//!
//! Algorithm family note: the ECIES constants exposed by objc2-security 0.3
//! only include the AESGCM family (`...SHA256AESGCM`); Apple's long-ago
//! deprecated `...SHA256AEAD` variant is no longer exported by that crate. We
//! take the AESGCM variant: still ECDH + HKDF + AES-GCM inside the SE hardware,
//! no hand-rolled ciphertext.
//!
//! Verification status: **compilation** is gated by the macOS job of the
//! `desktop-build` workflow (`tauri build` on a macos-latest runner) — this repo
//! has no macOS hardware, and the objc2-family crates cannot be compiled on
//! Linux (`objc2` explicitly rejects non-Apple targets, even `cargo check`
//! fails); **runtime** behavior is judged by real-hardware spike output (the
//! §5.2 probes have not been run, conclusions pending backfill).

// Core Foundation types go through the direct objc2-core-foundation dependency
// (objc2-foundation does not re-export them at its root).
use objc2_core_foundation::{CFBoolean, CFData, CFDictionary, CFRetained, CFType};
use objc2_security::{
    kSecAttrAccessControl, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, kSecAttrApplicationTag,
    kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey,
    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, kSecReturnRef,
    SecAccessControl, SecAccessControlCreateFlags, SecItemCopyMatching, SecItemDelete, SecKey,
    SecKeyAlgorithm,
};
use std::ptr::NonNull;
use zeroize::Zeroizing;

use persona_core::{
    BiometricKeyWrapper, BiometricWrapCapability, BiometricWrapError, WrapPlatform,
};

/// Application tag of the SE key (uniquely identifies this app's wrap key
/// within the keychain)
const KEY_TAG: &[u8] = b"persona.vault-wrap.v1";

/// ECIES algorithm: cofactor + variable-length IV + X9.63 KDF + SHA-256 +
/// AES-GCM (the same algorithm family used for SE wrapping by 1Password/age)
///
/// Uniform SAFETY precondition for every `unsafe { kSec… }` static read in this
/// file: these extern statics are process-level constants exported by
/// Security.framework (references to immutable CFStrings); the framework
/// guarantees their validity and immortality — the read itself requires unsafe
/// under Rust rules, but the value semantics carry no risk.
fn ecies_algorithm() -> &'static SecKeyAlgorithm {
    unsafe { kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM }
}

pub fn spike_enabled() -> bool {
    std::env::var_os("PERSONA_BIOMETRIC_SE_SPIKE").is_some_and(|v| v == "1")
}

/// Spike-gated assembly entry point (called by `biometric::key_wrapper`)
pub fn spike_wrapper_if_enabled() -> Option<SeKeyWrapper> {
    if spike_enabled() {
        Some(SeKeyWrapper)
    } else {
        None
    }
}

/// CFError wording. Codes such as `errSecMissingEntitlement (-34018)` and
/// `errSecUserCanceled (-25293)` are read from the CFError code (Security
/// puts the OSStatus into the CFError code verbatim) — both the spike report
/// and error triage depend on this.
fn cf_error_context(step: &str, err: *mut objc2_core_foundation::CFError) -> String {
    if err.is_null() {
        format!("{step}: failed with null CFError")
    } else {
        // SAFETY: the caller guarantees err points to a valid CFError
        let e = unsafe { &*err };
        format!("{step}: os_status={}", e.code())
    }
}

/// The user hit cancel in the system dialog (`errSecUserCanceled = -25293`).
/// Only cancellation goes through the silent fallback; all other failures are
/// treated as "wrap invalid" (see design doc §3.4).
const ERR_SEC_USER_CANCELED: i64 = -25293;
/// Item not found (`errSecItemNotFound`): the idempotent success of a delete.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

fn is_user_cancelled(context: &str) -> bool {
    context.contains(&ERR_SEC_USER_CANCELED.to_string())
}

/// AccessControl: private-key operations must go through biometrics (current
/// enrollment set) or the system password fallback
fn access_control() -> std::result::Result<CFRetained<SecAccessControl>, BiometricWrapError> {
    let mut err: *mut objc2_core_foundation::CFError = std::ptr::null_mut();
    // SAFETY: framework constant static (uniform precondition, see
    // ecies_algorithm docs)
    let protection: &CFType = unsafe { kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly };
    let flags = SecAccessControlCreateFlags::PrivateKeyUsage
        | SecAccessControlCreateFlags::BiometryCurrentSet;
    // SAFETY: both inputs are framework constants/flag bits, and the out error
    // pointer is owned by this function
    let acl = unsafe { SecAccessControl::with_flags(None, protection, flags, &mut err) };
    acl.ok_or_else(|| BiometricWrapError::Platform(cf_error_context("access control create", err)))
}

/// Find an existing wrap key; None if absent
fn find_key() -> Option<CFRetained<SecKey>> {
    let tag = CFData::from_bytes(KEY_TAG);
    // SAFETY: a query dictionary built from framework constant statics (uniform
    // precondition, see ecies_algorithm docs)
    let query = unsafe {
        CFDictionary::<CFType, CFType>::from_slices(
            &[
                kSecClass.as_ref(),
                kSecAttrApplicationTag.as_ref(),
                kSecReturnRef.as_ref(),
            ],
            &[
                kSecClassKey.as_ref(),
                tag.as_ref(),
                CFBoolean::new(true).as_ref(),
            ],
        )
    };
    let mut found: *const CFType = std::ptr::null_mut();
    // SAFETY: query is a valid dictionary; found is owned by this function and
    // ownership is transferred after Ok
    let status = unsafe { SecItemCopyMatching(query.as_opaque(), &mut found) };
    if status == 0 && !found.is_null() {
        // SAFETY: on success, SecItemCopyMatching leaves found as a retained
        // CFType (kSecReturnRef -> SecKeyRef); ownership is transferred as SecKey
        NonNull::new(found as *mut SecKey).map(|nn| unsafe { CFRetained::from_raw(nn) })
    } else {
        None
    }
}

/// Generate (or retrieve) the Secure Enclave wrap key
fn generate_or_find_key() -> std::result::Result<CFRetained<SecKey>, BiometricWrapError> {
    if let Some(key) = find_key() {
        return Ok(key);
    }
    let acl = access_control()?;
    let tag = CFData::from_bytes(KEY_TAG);
    let key_size = objc2_core_foundation::CFNumber::new_i32(256);
    // SAFETY: a parameters dictionary built from framework constant statics
    // (uniform precondition, see ecies_algorithm docs)
    let parameters = unsafe {
        CFDictionary::<CFType, CFType>::from_slices(
            &[
                kSecAttrKeyType.as_ref(),
                kSecAttrKeySizeInBits.as_ref(),
                kSecAttrTokenID.as_ref(),
                kSecAttrIsPermanent.as_ref(),
                kSecAttrAccessControl.as_ref(),
                kSecAttrApplicationTag.as_ref(),
            ],
            &[
                kSecAttrKeyTypeECSECPrimeRandom.as_ref(),
                key_size.as_ref(),
                kSecAttrTokenIDSecureEnclave.as_ref(),
                CFBoolean::new(true).as_ref(),
                acl.as_ref(),
                tag.as_ref(),
            ],
        )
    };
    let mut err: *mut objc2_core_foundation::CFError = std::ptr::null_mut();
    // SAFETY: parameters is valid; err is owned by this function
    let key = unsafe { SecKey::new_random_key(parameters.as_opaque(), &mut err) };
    key.ok_or_else(|| {
        // Under ad-hoc signing -34018 is a plausible expectation: the spike
        // exists precisely to catch this code
        BiometricWrapError::Platform(cf_error_context("SecKeyCreateRandomKey (route B')", err))
    })
}

/// ECIES wrap (public key, no dialog)
fn ecies_wrap(key: &SecKey, plaintext: &[u8]) -> std::result::Result<Vec<u8>, BiometricWrapError> {
    // SAFETY: key is a valid SecKey; err is owned by this function
    let public = unsafe { key.public_key() }
        .ok_or_else(|| BiometricWrapError::Platform("SecKeyCopyPublicKey returned None".into()))?;
    let data = CFData::from_bytes(plaintext);
    let mut err: *mut objc2_core_foundation::CFError = std::ptr::null_mut();
    // SAFETY: public ECIES encryption, no user interaction
    let ciphertext = unsafe { public.encrypted_data(ecies_algorithm(), &data, &mut err) };
    ciphertext
        .map(|d| d.to_vec())
        .ok_or_else(|| BiometricWrapError::Platform(cf_error_context("ECIES wrap", err)))
}

/// ECIES unwrap (private key: the SE enforces biometrics/system password at
/// this moment)
fn ecies_unwrap(key: &SecKey, payload: &[u8]) -> std::result::Result<Vec<u8>, BiometricWrapError> {
    let ciphertext = CFData::from_bytes(payload);
    let mut err: *mut objc2_core_foundation::CFError = std::ptr::null_mut();
    // SAFETY: private-key operation; the Secure Enclave enforces user
    // authentication at this moment (biometryCurrentSet)
    let plaintext = unsafe { key.decrypted_data(ecies_algorithm(), &ciphertext, &mut err) };
    let plaintext = match plaintext {
        Some(d) => d,
        None => {
            let detail = cf_error_context("ECIES unwrap", err);
            if is_user_cancelled(&detail) {
                return Err(BiometricWrapError::UserCancelled);
            }
            // Everything else (including the key being permanently invalidated
            // by the SE after a fingerprint change) is treated as wrap invalid
            return Err(BiometricWrapError::Platform(detail));
        }
    };
    Ok(plaintext.to_vec())
}

/// Spike-specific probe output (consumed by the `biometric_wrap_spike`
/// command): per-step OSStatus/verdicts, to be pasted back into design doc
/// §5.2 after running on real hardware
pub struct SpikeStep {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// Run all spike probes (probes 1/1b/2a/2b/3/4/5 from design doc §5.2;
/// "unwrap after deleting one fingerprint" requires a person on real hardware to
/// touch the biometric enrollment, so it is a manual control: run this function
/// once, delete one fingerprint, run it again — step 2b must fail for
/// biometryCurrentSet to be considered effective).
/// The "after restart" dimension of step 3 likewise comes from comparing two
/// consecutive runs of this function.
pub fn run_spike() -> Vec<SpikeStep> {
    let mut steps = Vec::new();

    // 1. Route B' key generation (access control + permanent SE)
    let key = match generate_or_find_key() {
        Ok(_) => {
            steps.push(SpikeStep {
                name: "1. SecKeyCreateRandomKey (SE, permanent, biometryCurrentSet)",
                ok: true,
                detail: "created or found".into(),
            });
            match find_key() {
                Some(key) => key,
                None => {
                    steps.push(SpikeStep {
                        name: "1b. find_key after create",
                        ok: false,
                        detail: "key not found right after creation".into(),
                    });
                    return steps;
                }
            }
        }
        Err(e) => {
            steps.push(SpikeStep {
                name: "1. SecKeyCreateRandomKey (SE, permanent, biometryCurrentSet)",
                ok: false,
                detail: e.to_string(),
            });
            return steps;
        }
    };

    // 2. ECIES roundtrip (wrap side prompts nothing, unwrap side triggers
    // biometrics)
    let probe = b"persona-spike-probe";
    let ciphertext = match ecies_wrap(&key, probe) {
        Ok(c) => {
            steps.push(SpikeStep {
                name: "2a. SecKeyCreateEncryptedData (ECIES, public key)",
                ok: true,
                detail: format!("{} bytes", c.len()),
            });
            c
        }
        Err(e) => {
            steps.push(SpikeStep {
                name: "2a. SecKeyCreateEncryptedData (ECIES, public key)",
                ok: false,
                detail: e.to_string(),
            });
            return steps;
        }
    };
    match ecies_unwrap(&key, &ciphertext) {
        Ok(plain) => {
            let ok = plain == probe;
            steps.push(SpikeStep {
                name: "2b. SecKeyCreateDecryptedData (prompts biometry)",
                ok,
                detail: if ok {
                    "roundtrip ok".into()
                } else {
                    "content mismatch".into()
                },
            });
        }
        Err(e) => steps.push(SpikeStep {
            name: "2b. SecKeyCreateDecryptedData (prompts biometry)",
            ok: false,
            detail: e.to_string(),
        }),
    }

    // 3. Persistence: this process can retrieve the existing key (find_key
    //    hitting = the keychain reference is alive; the full "after restart"
    //    verification = terminate this process and run the spike again, then see
    //    whether this step still reports found)
    steps.push(SpikeStep {
        name: "3. find_key (persistence probe)",
        ok: find_key().is_some(),
        detail: "run this spike again after restarting the app to prove cross-restart persistence"
            .into(),
    });

    // 5. Control group A (item 5 of design doc §5.2): DP keychain + AccessControl
    //    is expected to return -34018 under ad-hoc signing — confirming that the
    //    signing pitfall baseline really exists
    steps.push(access_control_probe());

    // 6. Delete path (both disable and invalidate self-heal go through it;
    //    idempotent)
    let delete_status = match delete_se_key() {
        Ok(()) => String::new(),
        Err(e) => e.to_string(),
    };
    steps.push(SpikeStep {
        name: "5. SecItemDelete (wrap key, idempotent)",
        ok: delete_status.is_empty(),
        detail: if delete_status.is_empty() {
            "deleted".into()
        } else {
            delete_status
        },
    });

    steps
}

/// Control group A probe: only construct an AccessControl (not even creating a
/// keychain item is enough to observe the signing gate — `SecAccessControlCreateWithFlags`
/// itself does not consume entitlements, the real -34018 shows up at
/// SecItemAdd/SecKeyCreateRandomKey with an ACL; this step records whether the
/// construction succeeded, and the primary judgement still rests on step 1's
/// real OSStatus).
fn access_control_probe() -> SpikeStep {
    match access_control() {
        Ok(_) => SpikeStep {
            name: "4. access control create (baseline, no keychain write)",
            ok: true,
            detail: "SecAccessControl created; -34018 (if any) surfaces at key creation (step 1)"
                .into(),
        },
        Err(e) => SpikeStep {
            name: "4. access control create (baseline, no keychain write)",
            ok: false,
            detail: e.to_string(),
        },
    }
}

/// Delete the SE wrap key in the keychain (idempotent: absence also counts as
/// success)
fn delete_se_key() -> std::result::Result<(), BiometricWrapError> {
    let tag = CFData::from_bytes(KEY_TAG);
    // SAFETY: a query dictionary built from framework constant statics (uniform
    // precondition, see ecies_algorithm docs)
    let query = unsafe {
        CFDictionary::<CFType, CFType>::from_slices(
            &[kSecClass.as_ref(), kSecAttrApplicationTag.as_ref()],
            &[kSecClassKey.as_ref(), tag.as_ref()],
        )
    };
    // SAFETY: query is valid
    let status = unsafe { SecItemDelete(query.as_opaque()) };
    if status == 0 || status == ERR_SEC_ITEM_NOT_FOUND {
        Ok(())
    } else {
        Err(BiometricWrapError::Platform(format!(
            "SecItemDelete os_status={status}"
        )))
    }
}

/// Hardware wrap wrapper for Secure Enclave route B'
pub struct SeKeyWrapper;

impl BiometricKeyWrapper for SeKeyWrapper {
    fn capability(&self) -> BiometricWrapCapability {
        BiometricWrapCapability::HardwareBound
    }

    fn is_available(&self) -> bool {
        // Available only when the hardware exists and a biometric enrollment is
        // on record (reusing the gate layer's LAContext probe)
        super::macos::available()
    }

    fn platform(&self) -> WrapPlatform {
        WrapPlatform::MacSecureEnclave
    }

    fn enrollment_fingerprint(&self) -> std::result::Result<[u8; 32], BiometricWrapError> {
        // The SE key's AccessControl carries .biometryCurrentSet: enrollment-set
        // drift is enforced as invalidation by the hardware (unwrap necessarily
        // fails). The core's fingerprint comparison is the second line of
        // defense, so this returns a fixed placeholder — we do not fabricate
        // enrollment-set state (Apple does not expose it, and what we could get
        // would not be reliable).
        Ok([0u8; 32])
    }

    fn wrap_payload(
        &self,
        master_key: &[u8; 32],
        _prompt: &str,
    ) -> std::result::Result<Vec<u8>, BiometricWrapError> {
        let key = generate_or_find_key()?;
        ecies_wrap(&key, master_key)
    }

    fn unwrap_payload(
        &self,
        payload: &[u8],
        prompt: &str,
    ) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricWrapError> {
        let _ = prompt; // the SE dialog wording is governed by AccessControl's prompt mechanism; the Rust side is audit-only
        let key = generate_or_find_key()?;
        let bytes = ecies_unwrap(&key, payload)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| BiometricWrapError::WrapInvalid)?;
        Ok(Zeroizing::new(arr))
    }

    fn delete_wrap_payload(&self, _payload: &[u8]) -> std::result::Result<(), BiometricWrapError> {
        delete_se_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real-hardware/CI probe entry point: `cargo test --lib
    /// spike_probes_print_report -- --ignored --nocapture`. The probe results
    /// are themselves the data (a GitHub runner is a VM with no Secure Enclave /
    /// Touch ID, so each step will honestly fail and log its OSStatus — that is
    /// exactly why the desktop-build macos job runs it: to backfill the real
    /// output into design doc §5.2); the assertion only guarantees "a report is
    /// produced" and does not gate on the ok field — the gating semantics live
    /// in the manual judgement of the spike output, not in the test.
    #[test]
    #[ignore = "需要真实 macOS 环境（Secure Enclave / Touch ID）；desktop-build macos job 按计划跑"]
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
