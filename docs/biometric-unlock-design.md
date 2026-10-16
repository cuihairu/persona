# Biometric Unlock Design (unlocking the vault via OS features)

> [English](biometric-unlock-design.md) | [中文](biometric-unlock-design.zh.md)

Status: design finalized 2026-09-26 + architecture landed; the hardware-bound
routes for both macOS (§5.2) and Windows (§6.3) are **implemented, pending an
on-device spike**.
This document is the expanded design for the "Biometric Unlock" chapter of `docs/THREAT_MODEL.md`.

## 0. Requirement origin

The user's exact words: "unlock by calling OS features", "macOS should support this too", "does Linux / Android / iOS all support it?".

Persona already has one biometric layer (landed 2026-09-21, all three desktop
platforms): **the master password is custodied in the OS keyring + an OS
authentication prompt acts as the gate**. This design upgrades it: "prompt
passes, so the password is retrieved" becomes "**the key is wrapped by
hardware, and the biometric prompt only appears at the moment of decryption**",
and it fills in the mobile roadmap.

## 1. Platform support matrix

| Platform  | API                                                                                                                                                | Binding strength                    | Status this round                                                                                                                 |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| iOS       | LocalAuthentication (LAContext) + Secure Enclave (CryptoKit `dataRepresentation`)                                                                  | Hardware-bound                      | Not wired up (three-platform native apps are in `mobile/`, biometric layer pending, §7.2)                                         |
| Android   | androidx BiometricPrompt + Android Keystore (`setUserAuthenticationRequired` + `setInvalidatedByBiometricEnrollment`)                              | Hardware-bound                      | Not wired up (three-platform native apps are in `mobile/`, biometric layer pending, §7.2)                                         |
| HarmonyOS | ArkTS `@ohos.userIAM.userAuth` + HUKS universal keystore (key properties bound to user authentication)                                             | Hardware-bound                      | Not wired up (three-platform native apps are in `mobile/`, biometric layer pending, §7.2; API semantics to be verified on-device) |
| macOS     | Secure Enclave P-256 + ECIES (route B', §5.2)                                                                                                      | Hardware-bound                      | **spike tooling ready, pending on-device**; currently stays on the gate layer                                                     |
| Windows   | First choice NCrypt/TPM "Passport key"; second choice WebAuthn platform authenticator reusing the ES256 primitives in `core/src/crypto/passkey.rs` | Hardware-bound (TPM)                | **spike tooling ready, pending on-device** (§6); currently stays on the Windows Hello gate layer                                  |
| Linux     | polkit `auth_self` (current) or direct fprintd D-Bus calls                                                                                         | **Gate only, no hardware wrapping** | Stays as-is (§7.1, honest limitation)                                                                                             |

Three tiers of binding strength (`BiometricWrapCapability`, defined in core, shared by all platforms):

1. **HardwareBound**: the private key wrapping the secret is non-exportable
   (SE / TPM / Keystore), and decryption is hardware-enforced to require user
   authentication (biometrics + system password fallback). A changed
   fingerprint / biometric enrollment set → the key is invalidated
   automatically.
2. **OsGateOnly**: the secret lives in the OS keyring and the OS authentication
   prompt is the gate — the gate is enforced by the system (not an app-layer
   self-check), but the keyring itself can be read by same-user processes
   (THREAT_MODEL already registers that Windows Credential Manager has no ACL).
3. **Unsupported**: no biometric hardware / no system authentication stack; the
   feature is hidden entirely (the frontend does not render the entry point
   rather than erroring).

## 2. Trust model

### 2.1 What it defends against

- **T1 a malicious same-user process reading the secret**: on the gate layer
  (current), reading the keyring entry = having the master password, which
  bypasses biometrics. On the hardware-bound layer, the process only gets the
  **wrapped blob** (ciphertext); without hardware authentication it cannot get
  the plaintext key.
- **T2 biometric enrollment drift**: a new fingerprint must not unlock an old
  wrap. Platform `biometryCurrentSet` / `setInvalidatedByBiometricEnrollment`
  semantics plus the enrollment fingerprint inside the core wrap envelope give
  double insurance (§3.2). **Windows has no corresponding platform semantics —
  this protection does not hold on Windows** (accepted; residual risk and
  mitigations in §6.2).
- **T3 brute-force probing**: failure counting / lockout lives in the core
  `UserAuth` layer; the hardware-bound path **does not bypass lockout**
  (see §3.4).

### 2.2 What it does not defend against (honest boundaries)

- **Not a replacement for the master password**: biometrics is the unlock
  factor; the master password always remains the recovery factor. After
  hardware failure / OS reinstall / biometric enrollment reset, the master
  password is the only way back in.
- **Stores no biometric templates**: templates always stay on the system side
  (SE / TEE / StrongBox); the app only gets the boolean "decryption succeeded"
  or the decryption capability itself.
- **No coercion resistance**: once hardware authentication passes, decryption
  happens — the same exposure level as 1Password.
- **No defense against system-level attackers** (userland rootkits running
  inside a malicious login session, kernel-level keyloggers): no local
  application model can defend against these.

## 3. Key flow

### 3.1 Current state (gate layer, live on all three desktop platforms)

```
enable:  verify master password → OS prompt → master password → keyring[persona-biometric]
unlock:  retrieve master password from keyring → OS prompt gate → authenticate_user(password)
```

Weakness: T1 — the OS prompt is only a gate; the keyring entry is the actual secret.

### 3.2 Target (hardware-bound layer)

```
enable (inside an unlocked session):
  master_key = PBKDF2(master password, salt)    ← already in memory (session unlocked)
  wrap_blob  = SE/TPM/Keystore wraps master_key ← hardware does NOT prompt when "wrapping"
  keyring[persona-biometric-wrap] = wrap_blob   ← stores ciphertext only, never the password

unlock (locked state):
  wrap_blob ← keyring
  master_key = hardware unwraps wrap_blob       ← hardware prompts biometrics "at the moment of decryption"
  service.authenticate_with_master_key(master_key)
```

Key difference: the actual secret goes from "the password in the keyring" to
"the private key inside the hardware"; the keyring only holds unreadable
ciphertext.

### 3.3 Wrap envelope format (defined in core, `core/src/auth/biometric_wrap.rs`)

```
BIOWRAP1 | u8 platform_tag | 32B enrollment_fp | u32le payload_len | payload
```

- `platform_tag`: 1 = macOS SecureEnclave, 2 = Windows TPM/Passport,
  3 = Linux (reserved), 0 = test mock; 4 = iOS Secure Enclave (CryptoKit),
  5 = Android Keystore, 6 = HarmonyOS HUKS (**reserved values** — enabled if
  a mobile native app reuses the BIOWRAP1 envelope; core-side `from_u8` does
  not recognize these values yet, as expected). Tag mismatch when unwrapping →
  `WrapInvalid`.
- `enrollment_fp`: the biometric enrollment-set fingerprint at enable time
  (provided by the platform; platforms where the hardware already enforces
  biometryCurrentSet may store a constant placeholder). Core compares it again
  at unwrap time; mismatch → `EnrollmentChanged` — even if the platform layer
  lets it slip through (the second line of defense in depth).
- `payload`: platform-private ciphertext. Core does not interpret the payload;
  the key flow only goes through the two trait methods `wrap_payload` /
  `unwrap_payload`, with intermediate values wrapped in `Zeroizing`.

### 3.4 Fallback chain (must not deadlock)

```
biometrics → system password/PIN (built into the platform prompt, e.g. LAPolicy.DeviceOwnerAuthentication)
          → master password (an entry the app layer always retains)
```

Automatic degradation on the core side when invalidated:

| Unwrap error                                     | Desktop behavior                                                                                                                                                                     |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `UserCancelled`                                  | Silently return to the unlock screen; the fingerprint button is kept                                                                                                                 |
| `EnrollmentChanged` / `WrapInvalid` / `Platform` | **Automatically delete the wrapped blob** + return the `BIOMETRIC_RESET` code → the frontend shows "biometric unlock has been reset; unlock with your master password and re-enable" |
| Lockout (5 failures)                             | Same semantics as the password path: `AccountLocked`; biometrics does not get through either                                                                                         |

Semantic alignment of `authenticate_with_master_key` with `authenticate_user`:
failure-count reset, session creation, `touch_sensitive`, audit Login — only
the password-verification step is replaced by "hardware has authenticated"; the
`password_change_required` forced-password-change flag **still takes effect**
(biometric unlock is also routed into the password-change flow).

## 4. Integration architecture

```
core (platform-agnostic)
  auth/biometric_wrap.rs
    BiometricWrapCapability / BiometricWrapError
    trait BiometricKeyWrapper { capability / is_available / enrollment_fingerprint
                                / wrap_payload / unwrap_payload / delete_wrap_payload }
    wrap-envelope encode/decode + MockKeyWrapper (for tests and CI)
  service.rs::authenticate_with_master_key()   ← key-unlock primitive (lockout/session/audit aligned)

desktop (host assembly)
  biometric.rs           existing OsBiometricProvider (gate layer, shared with the SSH agent)
  biometric/macos_se.rs  Secure Enclave route B' implementation (cfg macos; spike-gated)
  biometric/windows_tpm.rs  Passport KSP route (cfg windows; spike-gated, §6)
  commands.rs            biometric_enable/_unlock dispatch by capability;
                         wrap blob goes to keyring[persona-biometric-wrap];
                         biometric_wrap_spike / biometric_tpm_spike development
                         commands (run probes on a real device)
```

Selection rule (`biometric_enable`): provider `capability()` is
`HardwareBound` and `is_available()` → hardware wrapping; otherwise → the gate
layer (the current password custody, behavior unchanged). `biometric_unlock`
picks which chain to run based on **which kind of entry exists** in the
keyring — the two are mutually exclusive, and the disable command deletes both.

## 5. macOS: route selection and spike (verify first, then implement)

### 5.1 The signing pitfall (why we can't just write it)

Any data protection keychain entry carrying `SecAccessControl` fails to
create/read under ad-hoc signing (Tauri dev / a build without a configured
certificate) with `errSecMissingEntitlement (-34018)`. 1Password/Bitwarden
ship Developer ID signing + entitlements; we have no certificate.

### 5.2 Three candidate routes

| Route | Mechanism                                                                                                                  | Persistence                                        | Certificate requirement    | Risk                                                  |
| ----- | -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- | -------------------------- | ----------------------------------------------------- |
| A     | DP keychain generic password + SecAccessControl(biometryCurrentSet)                                                        | Survives reboot                                    | Developer ID + entitlement | -34018 under ad-hoc (known)                           |
| B     | **Non-permanent** SE key (`SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave` + `kSecAttrIsPermanent: false`) + ECIES | ⚠️ Private key destroyed when the process exits    | None                       | Key cannot be recreated; the blob bricks after reboot |
| B'    | **Permanent** SE key (same as above but `IsPermanent: true` + AccessControl)                                               | Survives reboot (keychain stores the SE reference) | Pending spike              | Unknown whether creation also hits -34018             |

**Research conclusion (2026-09-26, no local Mac so no on-device verification)**:
the literal route B (non-permanent key) keeps its private key **alive only
while the process lives** — SE persistence happens only with
`kSecAttrIsPermanent: true`; CryptoKit's
`SecureEnclave.P256.PrivateKey.dataRepresentation` (the shape age-plugin-se
and friends use) can export "a key blob only this machine's SE can unwrap",
sidestepping the keychain, but that export is a Swift-CryptoKit-only API — the
Security.framework C interface (the reachable surface for Rust objc2-security)
**has no equivalent**.

**spike objective** (on-device macOS; launch with
`PERSONA_BIOMETRIC_SE_SPIKE=1`, then invoke the `biometric_wrap_spike`
command, which reports OSStatus item by item). Mapping of probes to design
items (the probe name is the `name` the command returns):

| Design item                              | Probe name                                                        | Notes                                                                                                                                                                                                                                                                                                           |
| ---------------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. B' key creation                       | `1. SecKeyCreateRandomKey (SE, permanent, biometryCurrentSet)`    | Permanent SE key + `.privateKeyUsage \| .biometryCurrentSet` AccessControl → record the OSStatus (if it is -34018, B' is blocked by signing too)                                                                                                                                                                |
| 1b. Findable after creation              | `1b. find_key after create`                                       | The keychain reference is immediately visible within the same process                                                                                                                                                                                                                                           |
| 2. ECIES roundtrip                       | `2a. SecKeyCreateEncryptedData` / `2b. SecKeyCreateDecryptedData` | B'/B: public-key wrapping (no prompt) → private-key unwrapping (biometric prompt); the algorithm is `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM` (objc2-security 0.3 only exports the AESGCM family; the older `...AEAD` is no longer exported — both are SE-internal ECDH+HKDF+AES-GCM) |
| 3. Persistence                           | `3. find_key (persistence probe)`                                 | **Restart the process and run the spike again**; still found at this step = the keychain reference survives restart                                                                                                                                                                                             |
| 4. Fingerprint-deletion control (manual) | (no automatic probe)                                              | Run a spike → delete a fingerprint in System Settings → run again: step 2b must fail for `biometryCurrentSet` to count as effective                                                                                                                                                                             |
| 5. Baseline                              | `4. access control create (baseline, no keychain write)`          | Construct the AccessControl only (construction itself does not need the entitlement; a real -34018, if it exists, shows up at step 1's key creation)                                                                                                                                                            |
| 6. Idempotent delete                     | `5. SecItemDelete (wrap key, idempotent)`                         | The delete path shared by disable / invalidation self-healing (idempotent, including `errSecItemNotFound`)                                                                                                                                                                                                      |

Control group A (DP keychain generic password + SecAccessControl) has no
automatic probe: -34018 under ad-hoc is a known baseline (§5.1), and this
design does not take route A anyway (no certificate).

Spike passes (route B' as hoped) → flip macos_se.rs's capability to
HardwareBound, so enable defaults to hardware wrapping; fails → the document
carries the real error code, macOS stays on the gate layer, and route A is
left for re-evaluation "when a Developer ID certificate exists".

### 5.3 Current macOS behavior and verification status (honest record)

Unchanged (gate layer): LAContext `DeviceOwnerAuthentication` (biometrics +
system password fallback) + keyring master-password custody. macos_se.rs is
committed to the repo, but the production path is not enabled by default — we
leave no half-finished work on the main unlock chain.

Compile verification: macos_se.rs is `cfg(target_os = "macos")` code, which
Linux CI (`ci.yml` desktop job, ubuntu-latest) never compiles at all; the
`objc2` crate refuses even `cargo check` on a non-Apple **host** target.
But a cross check works: `cargo check --target aarch64-apple-darwin --lib`
is usable on Linux — `cargo check` does not link, so the ObjC exception
helper files cc-rs wants to compile are stubbed out with a compiler that
exits 0
(`CC_aarch64_apple_darwin=true cargo check --target …`), letting rustc
fully type-check the module. **This verification ran green on 2026-09-26
(check + clippy `-D warnings`, both green)**, and it caught and fixed three
real errors on the spot: CF types must go through the direct dependency
`objc2-core-foundation` (objc2-foundation does not re-export them at the
root), `kSec…` extern static reads need `unsafe` at each site, and the out
parameter of `SecItemCopyMatching` is `*mut *const CFType`. Final linking and
runtime behavior are verified only in the macOS job of `desktop-build`
(`tauri build` on a macos-latest runner) and in the on-device spike.

**GitHub runner probe measurement (2026-09-26, desktop-build)**: macos-latest
is a VM with no Secure Enclave, and probe 1 of
`spike_probes_print_report` (`cargo test --lib -- --ignored --nocapture`)
fails outright: `SecKeyCreateRandomKey (route B'): os_status=-25293`
(`errSecAuthFailed` — creating an SE key needs both SE hardware and a signed
entitlement, and the runner has neither). What this output proves is "compiles
/ links under a real Apple toolchain, and the probe path works"; **SE
behavior itself is still only settled by the on-device spike**, and the
decision that the production unlock chain does not include B' by default is
unchanged.

## 6. Windows: Passport KSP (implementation committed, pending an on-device spike)

The route choice is unchanged: **first choice NCrypt `Microsoft Passport Key
Storage Provider`** (TPM-protected private key, user authentication enforced by
the Hello policy), second choice WebAuthn platform authenticator. The first
choice is implemented as
`desktop/src-tauri/src/biometric/windows_tpm.rs`, **spike-gated** (wired up
only with `PERSONA_BIOMETRIC_TPM_SPIKE=1`); the production unlock chain
defaults to the Windows Hello gate layer — the default does not switch before
on-device behavior is verified.

### 6.1 Implementation notes

Open `MS_KEY_STORAGE_PROVIDER`, create a 2048-bit RSA user key under it, and
pin three attributes:

| Property                    | Value                        | Why                                                                                                                                                                         |
| --------------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NCRYPT_KEY_USAGE_PROPERTY` | `NCRYPT_ALLOW_DECRYPT_FLAG`  | Open only the private key's "decrypt" direction (= wrap/unwrap); signing is not granted                                                                                     |
| `NCRYPT_UI_POLICY_PROPERTY` | `NCRYPT_UI_PROTECT_KEY_FLAG` | Every use of the private key must pass Windows Hello user verification before the TPM lets it through                                                                       |
| the `dwFlags` for ↑         | **`NCRYPT_PERSIST_FLAG`**    | The policy must be persisted with the key, otherwise it applies only within the process — after restart unwrapping **no longer prompts Hello**, a silent security downgrade |
| `NCRYPT_LENGTH_PROPERTY`    | 2048                         | Unwrapping is a user-perceived path; key length trades latency                                                                                                              |

Wrapping = `NCryptEncrypt` (RSA public-key direction, **no prompt**);
unwrapping = `NCryptDecrypt` (private-key direction, **Hello prompts at this
moment**). Only the two "absent" states of `NCryptOpenKey`
(`NTE_BAD_KEYSET` / `ERROR_NOT_FOUND`) allow automatic rebuild; every other
error is propagated, not papering over a real failure.

**One deliberate difference from macOS B'**: the unwrap path **only** calls
`NCryptOpenKey` and does not auto-create a key. On the macOS side, unwrapping
also goes through `generate_or_find`, so when the key does not exist it first
creates a fresh key and only then fails on ECIES — leaving behind an orphan key
nobody uses, while disguising a real failure ("the blob came from a different
machine / the user cleared Passport keys") as a plain decryption error. On the
Windows side, absence means `WrapInvalid`, and the host's handling (auto-delete
the blob and fall back to the master password, §3.4) fits that semantics.

### 6.2 Capability gap: enrollment-set drift (T2) has no platform-level enforcement on Windows

**This is a substantive gap between this route and macOS B', recorded honestly
in both the document and the code comments.**

Apple's `biometryCurrentSet` permanently invalidates the old SE key after a
fingerprint is changed. Windows has no corresponding API:
`NCRYPT_UI_PROTECT_KEY_FLAG` enforces "user verification on every use", but
**verifying with a newly registered fingerprint still lets the old key through**.
So `TpmKeyWrapper::enrollment_fingerprint()` can only return a fixed
placeholder (all zeros) — there is no real value for core's second comparison to
check against. It is shaped like the macOS placeholder, but it is a different
beast:

| Platform | Placeholder returned | Real guarantee behind the placeholder                                                                                |
| -------- | -------------------- | -------------------------------------------------------------------------------------------------------------------- |
| macOS    | `[0u8; 32]`          | Platform-level `biometryCurrentSet` is already enforced; the placeholder is only a second line of defense            |
| Windows  | `[0u8; 32]`          | **The platform does nothing**; there is no guarantee behind the placeholder, and the second line of defense is empty |

Residual risk (written honestly): an attacker who has the local login session
and can complete **one** Hello verification (any enrolled fingerprint or PIN)
can unwrap the old blob — this anti-coercion property of "fingerprint change
means invalidation" does not hold on Windows. The mitigations are the master
password backstop plus the fact that the wrapped blob in the keyring is only
ciphertext (a same-user process can read it but cannot open it unless it can
make Hello pass). This is an **accepted** gap, not a bug to fix:
"invalidation on enrollment-set change" can only come if an equivalent API
appears on the Windows side (the WebAuthn route has no such semantics either).

### 6.3 spike probes (on-device; launch with `PERSONA_BIOMETRIC_TPM_SPIKE=1`, then invoke the

`biometric_tpm_spike` command, which reports HRESULT item by item)

| Design item                          | Probe name                                                    | Notes                                                                                                                                                                      |
| ------------------------------------ | ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. KSP openable                      | `1. NCryptOpenStorageProvider (Microsoft Passport KSP)`       | Cannot open = this machine has no Passport KSP; everything below is meaningless                                                                                            |
| 2. Algorithm capability              | `2. NCryptIsAlgSupported (RSA, NCRYPT_ALLOW_DECRYPT_FLAG)`    | Whether the provider supports the private-key decrypt direction                                                                                                            |
| 3. Prerequisite                      | `3. Windows Hello availability (UserConsentVerifier)`         | Whether the subsequent `NCRYPT_UI_PROTECT_KEY_FLAG` can be persisted is doubtful when no PIN/fingerprint is enrolled                                                       |
| 4. Key creation + policy persistence | `4. NCryptCreatePersistedKey (RSA-2048, UI policy persisted)` | Record the HRESULT (only a real device tells whether the `NCRYPT_PERSIST_FLAG` combination is accepted)                                                                    |
| 4b. Findable after creation          | `4b. NCryptOpenKey after create`                              | The keychain reference is immediately visible within the same process                                                                                                      |
| 5. roundtrip                         | `5a. NCryptEncrypt` / `5b. NCryptDecrypt`                     | 5a goes the public-key direction and **must not prompt**; 5b goes the private-key direction and **must prompt Hello** (this step is the premise the whole route stands on) |
| 6. Persistence                       | `6. NCryptOpenKey (persistence probe)`                        | **Restart the process and run the spike again**; still found at this step = the key survives restart and the policy takes effect across restart                            |
| 7. Idempotent delete                 | `7. NCryptDeleteKey (idempotent, called twice)`               | The delete path shared by disable / invalidation self-healing; deleting twice in a row must both succeed (absent = success)                                                |

**Manual control** (no automatic probe): run a spike → **delete a fingerprint**
in System Settings → run again: step 5b must still succeed (Windows, unlike
macOS, does not invalidate on fingerprint deletion — this is exactly the §6.2
gap), and step 3 should still be available.

Compile verification: same approach as §5.3 — the `x86_64-pc-windows-msvc`
target can be `cargo check`ed on Linux (no linking); stub out the C toolchain
cc-rs wants and rustc fully type-checks the module. Two more steps than the
macOS side (recipe verified on 2026-09-26): `CC_x86_64_pc_windows_msvc=true`
as usual; the archiver cannot be `llvm-ar` (not present on this machine, and
cc-rs passes `-out:<lib>`-style arguments for MSVC targets) — stub
`AR_x86_64_pc_windows_msvc` with a small script that parses the `-out:`
argument and touches out that file; additionally, tauri-build's resource
compilation goes through embed-resource, which looks for `llvm-rc`, so put a
stub in PATH that "parses the `/fo` argument, touches the output, exits 0".
**This verification caught two real errors on the spot** (the dwflags of
`NCryptDeleteKey` is a `u32` in windows-rs 0.61, not `NCRYPT_FLAGS`; an unused
`Result` in `Drop`), and after fixing them check + clippy `-D warnings` are both
green. Runtime behavior is verified only in the Windows job of `desktop-build`
and in the on-device spike.

**GitHub runner measurement (2026-09-26, desktop-build)**: the test profile
**cannot start its binary** on the Windows runner — `0xc0000139
STATUS_ENTRYPOINT_NOT_FOUND` (the native loader dependency of the Tauri test
binary is missing an export in the runner environment; this repo has never
compiled the test profile on Windows before). So the runtime behavior of
Passport KSP **cannot be obtained on the runner**; the probes are only
feasible on a real device / a regular Windows session (or by invoking the
`biometric_tpm_spike` command in an app launched with
`PERSONA_BIOMETRIC_TPM_SPIKE=1`). CI's probe step is therefore marked
`continue-on-error` (the compile-time signal is still there; runtime
conclusions come only from a real device).

The second-choice route (WebAuthn platform authenticator) is **still
unimplemented**; the design intent is preserved in the original §6 plan: make
credential (UV required) → get assertion at unlock time (hardware prompts
Hello) → gate the DPAPI wrapping layer with credential binding. It is weaker
than Passport Key (the assertion only proves "holding the credential + user
present"; the wrapped key itself still needs a separate DPAPI/TPM layer), and
it likewise has no enrollment-set-drift semantics from §6.2.

- `UserConsentVerifier` (boolean confirmation) is only fit for use as the
  current **gate layer**.
- **Explicit non-goal**: it cannot and should not replace Windows logon
  verification — a credential provider is a COM component loaded by LogonUI,
  which no third party can stand in for; what we are building is "unlocking the
  Persona vault", not "logging into Windows".

## 7. Linux / mobile

### 7.1 Linux current state (honest limitation)

polkit `auth_self` gate (hand-written CheckAuthorization, avoiding
CVE-2026-78422). **No hardware key wrapping**: there is no unified
application-layer API over SE/StrongBox/TPM; driving TPM2.0 directly
(tss-esapi) is severely fragmented across desktop distros, so it is not a
default dependency. The keyring is the secret service
(GNOME Keyring/KWallet), whose entries can be read by same-session processes.
Conclusion: Linux is pinned at the OsGateOnly tier, and the documents do not
claim hardware binding (the Linux branch of `biometric.rs` is an OsGateOnly
stub wrapper — wrap/unwrap always return `Unsupported`, and enable/unlock use
the gate layer accordingly). Direct fprintd D-Bus calls (system bus
`net.reactivated.fprint`, object `/net/reactivated/fprint/device`) are an
alternative to polkit (one less policy dependency); the only gain is not
installing polkit, so it is not done for now.

### 7.2 iOS / Android / HarmonyOS (three-platform native apps are in `mobile/`, biometric layer pending)

Technical decision (settled by the user, 2026-09-26): each of the three mobile
platforms is developed with its own **platform-native technology** — iOS
Swift/SwiftUI, Android Kotlin/Jetpack Compose, HarmonyOS ArkTS/ArkUI
(HarmonyOS NEXT is incompatible with Android APKs, so native it is; older
Harmony also aligns with the native route, with no APK-compatibility
dependency). **No Flutter/Rust FFI middleman**: biometrics and key storage are
deep platform features, and only native APIs give the full semantics
(`biometryCurrentSet`, `setInvalidatedByBiometricEnrollment`); a middleman
layer only loses semantics and widens the attack surface. This design's trait
contract (capability tiers, envelope format, fallback-chain semantics) serves
as the specification the three native implementations follow, not as a code
dependency:

- iOS (Swift): CryptoKit `SecureEnclave.P256` + `.biometryCurrentSet`
  AccessControl; `dataRepresentation` goes into an app-managed file (not the
  keychain, sidestepping the entitlement), and LAContext only provides the UI
  prompt — isomorphic to route B' in §5 of this file; with Swift as the host
  language, CryptoKit's `dataRepresentation` is directly usable (the
  "Security.framework C interface has no equivalent" limitation mentioned in
  §5.1 does not exist for Swift).
- Android (Kotlin): Keystore `setUserAuthenticationRequired(true)` +
  `setInvalidatedByBiometricEnrollment(true)` (API 24/28 semantics);
  BiometricPrompt triggers the gate; the wrapped blob is written directly from
  the Kotlin side to EncryptedSharedPreferences/Keystore.
- HarmonyOS (ArkTS): `@ohos.userIAM.userAuth` drives the biometric prompt
  (fingerprint/face, SYSTEM_PIN fallback); key wrapping goes through HUKS
  (`@ohos.security.huks`) — generate a hardware-protected key and use
  user-authentication tags (AuthAccess/UserAuthType etc.) to require
  "biometrics must pass before the key is used"; the invalidation semantics on
  enrollment-set change are settled only by on-device verification (HUKS
  behavior differs across API versions; spike first before implementing:
  record the challenge flow, the invalidation granularity, and whether
  EquivalentX/SecureEnclave-grade hardware isolation is supported). The
  wrapped blob is stored from the ArkTS side in HUKS/local encrypted storage.
- The end-to-end encrypted sync protocol across the three platforms (envelope
  format, key-derivation parameters) is implemented natively per the protocol
  spec; cross-platform interoperability is settled by protocol conformance.

## 8. Landing checklist for this round (2026-09-26)

- [x] Design document (this one)
- [x] core: `BiometricKeyWrapper` trait + envelope encode/decode + `MockKeyWrapper`
      (100% line/branch, measured with `cargo llvm-cov`; plus 6 service-layer
      cases covering wrap→unlock end to end and the three gates)
- [x] core: `authenticate_with_master_key` (lockout / failure count / session /
      audit / forced-password-change flag aligned with the password path) +
      `derive_master_key_for_wrap` + `unlock_with_master_key`
- [x] desktop: capability-dispatched enable/unlock/disable/status +
      wrap-blob keyring isolation (`persona-biometric-wrap`) + delete the blob
      on password change + 8 command-layer cases (enable stores ciphertext,
      including an assertion that the two entry types are mutually exclusive /
      unlock closed loop / enrollment-set drift / user cancel / corrupt blob /
      invalidation on password change / spike reports Unsupported off-macOS /
      spike reports Unsupported off-Windows)
- [x] desktop: macos_se.rs (route B', spike-gated; **compile verification
      passed** — Linux cross check/clippy, see §5.3) + `biometric_wrap_spike`
      command
- [x] desktop: windows_tpm.rs (Passport KSP first-choice route, spike-gated;
      **compile verification passed** — Linux cross check, see the end of §6.3) + `biometric_tpm_spike` command (probes 1/2/3/4/4b/5a/5b/6/7)
- [x] desktop: the status surface exposes the wrap tier (hardware-bound /
      os-gate), EnrollmentChanged auto-degradation + frontend branching for
      `BIOMETRIC_RESET` / `BIOMETRIC_CANCELLED` (unlock screen: RESET hides the
      button, CANCEL keeps it silently; settings page tier row)
- [x] spike probes wired into CI (`spike_probes_print_report` in the
      desktop-build macos/windows jobs, `--ignored --nocapture`; an honest
      failure on a VM is produced as-is, macOS measurement in §5.3)
- [ ] macOS on-device spike (§5.2 probes 1/1b/2a/2b/3/4/5 + manual
      fingerprint-deletion control; runner VM measurement in §5.3 — no SE, so
      probe 1 already hits errSecAuthFailed, which is not evidence of SE
      behavior) → conclusions backfilled into §5.2 of this document and
      THREAT_MODEL
- [ ] Windows on-device spike (§6.3 probes 1/2/3/4/4b/5a/5b/6/7 + manual
      fingerprint-deletion control; runner measurement at the end of §6.3 — the
      test binary cannot start with 0xc0000139, so runtime conclusions can only
      come from a real device) → conclusions backfilled into §6 of this document
      and THREAT_MODEL (including whether the §6.2 gap holds as registered)
- [ ] Windows second-choice route (WebAuthn platform authenticator) —
      **deferred**: weaker than Passport Key with no extra benefit beyond
      §6.2, so wait for the first-choice route's on-device conclusion
- [ ] iOS/Android/HarmonyOS platform biometric unlock integration — the
      three-platform native apps are committed (`mobile/`: iOS Swift/SwiftUI +
      Android Kotlin + HarmonyOS ArkTS, no Flutter/FFI middleman — §7.2
      technical decision); this design's hardware-bound layer is not yet wired
      into the three platforms
