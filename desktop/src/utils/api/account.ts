import { invoke } from './invoke';

import type {
  ApiResponse,
  WorkspaceSettings,
  AccountRegistrationResponse,
  AccountSrpRegisterResponse,
  AccountSrpChallengeResponse,
  AccountSrpVerifyResponse,
  AccountPasskeyCreationOptions,
  AccountPasskeyLoginOptions,
  AccountSessionEvidence,
  AccountDevicesList,
  AccountRecoveryCodes,
  AccountSessionInfo,
} from '@/types';

export const accountApi = {

  // -------------------------------------------------------------------------
  // Account system (M2 scaffolding: a proxy seam aligned with the server
  // /api/v1/accounts/* contract; the tauri proxy command layer lands with the
  // M2 account UI batch; account/sync features are off by default)
  // -------------------------------------------------------------------------

  /** Public registration of a new account (no authentication). On success returns account_id plus basic info. */
  async accountRegister(
    request: { username: string; display_name?: string }
  ): Promise<ApiResponse<AccountRegistrationResponse>> {
    return invoke('account_register', { request });
  },


  /** Passkey registration options (public endpoint). The server issues WebAuthn
   * creation options with a challenge (a one-time 120s challenge, matched
   * strictly at register time). */
  async accountPasskeyCreateOptions(
    account_id: string,
    request: {
      rp_id: string;
      rp_name?: string;
      user_handle: string;
      user_name?: string;
      user_display_name?: string;
    }
  ): Promise<ApiResponse<AccountPasskeyCreationOptions>> {
    return invoke('account_passkey_create_options', { account_id, request });
  },


  /** Completes passkey registration (public endpoint). Submits the authenticator
   * attestation; the server performs full RP-side verification and then stores
   * the public key material. */
  async accountPasskeyRegister(
    account_id: string,
    request: {
      attestation_response: { credentialId: string; attestationObject: string };
      client_data_json: string;
      origin: string;
    }
  ): Promise<ApiResponse<{ passkey_id: string }>> {
    return invoke('account_passkey_register', { account_id, request });
  },


  /** Passkey login options (public endpoint, first step of the login ceremony).
   * Exchanges a server challenge (one-time, 120s) for the credential id, to be
   * consumed at assertion time. */
  async accountPasskeyLoginOptions(
    account_id: string,
    request: { credential_id: string }
  ): Promise<ApiResponse<AccountPasskeyLoginOptions>> {
    return invoke('account_passkey_login_options', { account_id, request });
  },


  /** SRP credential registration (requires Bearer). Registers the SRP salt+verifier of a device within the account. */
  async accountSrpRegister(
    account_id: string,
    request: { device_name: string; salt: string; verifier: string }
  ): Promise<ApiResponse<AccountSrpRegisterResponse>> {
    return invoke('account_srp_register', { account_id, request });
  },


  /** SRP challenge request (public endpoint, a login step). Starts the account SRP login handshake. */
  async accountSrpChallenge(
    account_id: string,
    request: { device_name: string; client_public: string }
  ): Promise<ApiResponse<AccountSrpChallengeResponse>> {
    return invoke('account_srp_challenge', { account_id, request });
  },


  /** SRP verification completion (public endpoint, a login step). Finishes the
   * handshake and returns a 15-minute SRP login token (usable as the Bearer for
   * account routing, or exchanged for a 24h session). */
  async accountSrpVerify(
    account_id: string,
    request: { session_id: string; client_proof: string }
  ): Promise<ApiResponse<AccountSrpVerifyResponse>> {
    return invoke('account_srp_verify', { account_id, request });
  },


  /** Wizard-style SRP credential registration: the passphrase is used in core to
   * derive salt+verifier and register them (the bootstrap Bearer falls back to
   * the static server token when the account session is missing). The frontend
   * never touches the wire values. */
  async accountSrpRegisterWithPassword(
    account_id: string,
    request: { device_name: string; password: string }
  ): Promise<ApiResponse<{ device_name: string }>> {
    return invoke('account_srp_register_with_password', { account_id, request });
  },


  /** Wizard-style SRP login: challenge/verify and the M2 checks are orchestrated
   * in core, and the 15-minute token is written straight to the keyring (the
   * response does not carry the token itself). */
  async accountSrpLogin(
    account_id: string,
    request: { device_name: string; password: string }
  ): Promise<ApiResponse<{ expires_in_secs: number; session_key_fingerprint: string }>> {
    return invoke('account_srp_login', { account_id, request });
  },


  /** Writes the account-domain binding: bind (after the wizard succeeds) / unbind
   * (signing out of the account, pass null). Reading goes through
   * getWorkspaceSettings (settings.account is returned directly). */
  async accountSetBinding(
    binding: { account_id: string; username: string; device_name?: string | null } | null
  ): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_account_binding', { binding });
  },


  /** Exchanges for a 24h session (orchestration command): the keyring's
   * 15-minute token serves as both Bearer and evidence, and the 24h session is
   * written straight to the keyring. The response does not carry the token
   * itself. */
  async accountExchangeSession(
    account_id: string
  ): Promise<ApiResponse<{ expires_in_secs: number }>> {
    return invoke('account_exchange_session', { account_id });
  },


  /** Signs out of the account (orchestration command): self-revokes the keyring
   * token (best effort on the server side) and clears the keyring.
   * revoked_on_server=false = there was nothing to revoke server-side. */
  async accountSignOut(account_id: string): Promise<ApiResponse<{ revoked_on_server: boolean }>> {
    return invoke('account_sign_out', { account_id });
  },


  /** Generates recovery codes (requires Bearer). Each call produces a fresh set of 8 and invalidates the previously unused ones. */
  async accountGenerateRecoveryCodes(
    account_id: string
  ): Promise<ApiResponse<AccountRecoveryCodes>> {
    return invoke('account_generate_recovery_codes', { account_id });
  },


  /** Verifies a recovery code (public endpoint). Single-use: it is marked as used after a successful verification. */
  async accountVerifyRecoveryCode(
    account_id: string,
    request: { code: string }
  ): Promise<ApiResponse<{ success: boolean }>> {
    return invoke('account_verify_recovery_code', { account_id, request });
  },


  /** Authorizes a device for the account (requires Bearer). Associates an already
   * registered sync device (matched by device_id + public key) with the account. */
  async accountAuthorizeDevice(
    account_id: string,
    request: { device_id: string; public_key: string }
  ): Promise<ApiResponse<{ id: string; status: string }>> {
    return invoke('account_authorize_device', { account_id, request });
  },


  /** Lists the devices authorized under the account (requires Bearer). */
  async accountListDevices(
    account_id: string
  ): Promise<ApiResponse<AccountDevicesList>> {
    return invoke('account_list_devices', { account_id });
  },


  /** Revokes a device under the account (requires Bearer). */
  async accountRevokeDevice(
    account_id: string,
    device_id: string
  ): Promise<ApiResponse<boolean>> {
    return invoke('account_revoke_device', { account_id, device_id });
  },


  /** Creates an account session (requires Bearer). Exchanges exactly one piece of
   * login evidence (the SRP 15-minute token or a passkey assertion) for a 24h
   * account session token. */
  async accountCreateSession(
    account_id: string,
    request: AccountSessionEvidence
  ): Promise<ApiResponse<AccountSessionInfo>> {
    return invoke('account_create_session', { account_id, request });
  },


  /** Revokes an account session (requires Bearer). Logs that session token out. */
  async accountRevokeSession(
    account_id: string,
    session_token: string
  ): Promise<ApiResponse<boolean>> {
    return invoke('account_revoke_session', { account_id, session_token });
  },
};
