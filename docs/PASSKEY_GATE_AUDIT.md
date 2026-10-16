# Passkey Gate Audit (Batch E Verification)

> [English](PASSKEY_GATE_AUDIT.md) | [中文](PASSKEY_GATE_AUDIT.zh.md)

Audit date: 2026-10-04. Scope: the passkey/WebAuthn capabilities of the browser-extension
track (TODO batch E: "Passkey gap verification + end-to-end tests"), checked against the
P1–P4 phases in [PASSKEYS_DESIGN.md](PASSKEYS_DESIGN.md) and the state of bridge protocol
v2/v3. Division of labour: the E1/E3 code and tests were delivered by the extension track
(batches A–D); this audit is responsible for **verifying each item + ruling + logging
residuals**.

## Verdict at a Glance

| Item                                      | Verdict                  | Evidence |
| ----------------------------------------- | ------------------------ | -------- |
| E1 Extension-side passkey create/assert dual-gate regression | ✅ Covered      | See §1 |
| E2 OS passkey provider (v3) on-device acceptance               | ⏸ Deferred (on-device prerequisite) | See §2 |
| E3 Cross-origin iframe passkey hook behavior                   | ✅ Design ruling: no injection | See §3 |

Net verdict: the v2/v3 protocol, core validation, dual gates, and audit metadata have no
unexpected gaps; the residuals are all on-device/platform prerequisites (E2, P4.2/P4.3) or
explicit non-goals (§4).

## 1. E1: Gesture Gate + Desktop Approval Dual-Gate Regression — Covered

- Extension message layer: `passkey_list` / `passkey_create` / `passkey_assert` are all
  authed messages (pairing + session HMAC); `passkeyCreate`/`passkeyAssert` forward the
  page-reported `user_gesture` verbatim (`nativeBridge.ts`). The extension test for the
  forwarding logic (`nativeBridge.test.ts`) covers only the `gesture=true` case; the
  two-way `true/false` gate cases live in the core bridge tests (cli `bridge.rs` protocol
  cases, including the `user_gesture_required` refusal path) and the assertion-selection
  item tests.
- Content layer: the confirmation UI is triggered after the
  `persona_passkey_create/list/assert` messages (`content.ts`), and the gesture comes from
  a real click.
- Core side: bridge protocol cases (cli bridge tests) plus desktop approval whitelist cases
  (the op and parsing tests in `desktop/src-tauri/src/passkey_bridge.rs`, including
  `parse_query` rejecting illegal ops). Both `passkey_create` and `passkey_assert` pass
  through `desktop_approval_gate` and the active-identity check.
- Audit: `passkey_asserted` carries `via=extension|os_provider` metadata (P4.4, locked by
  the protocol tests).

Verification: `npx jest` inside `browser/chromium-extension` (11 suites, 129 cases, all green)

- `npx tsc --noEmit`; the extension tests include a manifest contract test (webauthnHook
  top-frame only, content.js all frames, ISOLATED world).

## 2. E2: OS Passkey Provider On-Device Acceptance — Deferred (Logged)

Same class of missing prerequisite as `FEATURE_GAP_ANALYSIS.md` #23/#24: the OS provider
needs real hardware — macOS (Signing & WebAuthn entitlement signing) and Windows
(Hello plugin)

- signing environment; the CI build/protocol surface already covers macOS/Windows
  (`ci.yml` includes a windows job, `desktop-build.yml` runs a macos/windows matrix), but
  the runners are VMs without Secure Enclave / Hello hardware, so they can only run protocol
  and core regression (P4.1/P4.4 are already closed there). On-device behavior still needs
  real-hardware acceptance. Deferred and logged; reactivation conditions: a macOS/Windows
  machine plus a Developer ID signing environment (see PASSKEYS_DESIGN §13.1 for the
  P4.2/P4.3 acceptance).

## 3. E3: Cross-Origin iframe Passkey — Design Ruling: No Injection

`all_frames: true` applies only to `content.js` in the ISOLATED world; `webauthnHook.ts`
in the MAIN world **stays top-frame only**. Basis for the ruling:

1. Wrapping every third-party iframe with a `navigator.credentials` layer is too much
   surface area, and cross-origin iframe passkey requests should go through the browser's
   native flow anyway (the best path when the user already has an OS/browser passkey);
2. Same-origin iframes (embedded login in an oauth popup, etc.) are covered by content.js's
   per-frame autofill mechanism (batch B) and do not use the WebAuthn hook;
3. The v3 provider path (P4.1) does not go through the content-script hook and is unrelated
   to iframes.

The ruling is **locked** by the manifest contract test (regression guard: `manifest.test.ts`
asserts webauthnHook is not injected into iframes). The iframe behavior is documented in the
README.

## 4. Remaining Gaps (All Logged, Out of Scope for This Batch)

| Item                                                             | Status                                                                                    | Owner                      |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | -------------------------- |
| P4.2 macOS provider / P4.3 Windows Hello plugin                 | On-device prerequisite                                                                     | Deferred (same as E2)      |
| Open question 1: selection-UI filtering when multiple identities match the same rp_id | Leaning toward active-identity filtering + a "show other identities" expansion      | PASSKEYS_DESIGN §14, pending |
| Open question 2: private-key backup format (custom JSON vs PKCS#12-class) | Stay on v1 custom + schema docs until the standard (CXF) is finalized            | Same as above              |
| Open question 3: a dedicated policy key `confirm_on_passkey_assert` | The policy key is not persisted; today it effectively goes through the separate desktop approval gate `PERSONA_BRIDGE_DESKTOP_APPROVAL`, to be revisited after P3 | Same as above |
| P4.5 CXF field reservation                                       | Planned: `foreign_key_ref` is not persisted and will not be implemented before the standard is finalized | Tracking item |
| Extension passkey interoperability with real sites (webauthn.io/GitHub) | No browser E2E harness yet; the on-device cross-check with batch B is still owed | Reactivate together with E2 |

## 5. Suggested Follow-Up Actions (Not Blocking Closure)

1. When a real-site regression tool is picked (a Playwright smoke test), make webauthn.io
   registration/assertion the first extension-track case (covering the GitHub multi-step
   login cross-check owed by batch B at the same time);
2. Open question 1 gets resolved as part of the desktop passkey management page iteration
   (P3 already exists);
3. No new OS provider code commitments before E2 is reactivated.
