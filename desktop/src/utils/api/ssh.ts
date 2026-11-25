import { invoke } from './invoke';

import type {
  ApiResponse,
  SshConfigAgentAnalysis,
  SshIntegrationStatus,
  SshAgentStatus,
  SshAgentKey,
  SshKeyInspection,
  SshKeyGenerated,
  SshKeyImported,
} from '@/types';

export const sshApi = {

  async getSshAgentStatus(): Promise<ApiResponse<SshAgentStatus>> {
    return invoke('get_ssh_agent_status');
  },


  async startSshAgent(masterPassword?: string): Promise<ApiResponse<SshAgentStatus>> {
    return invoke('start_ssh_agent', { request: { master_password: masterPassword } });
  },


  async stopSshAgent(): Promise<ApiResponse<boolean>> {
    return invoke('stop_ssh_agent');
  },


  /** Three-state detection of the IdentityAgent anchor block in ~/.ssh/config (pure read, no unlock) */
  async sshAgentIntegrationStatus(): Promise<ApiResponse<SshIntegrationStatus>> {
    return invoke('ssh_agent_integration_status');
  },


  /** One-click enable: idempotently upserts the anchor block (touches only what is inside the block, leaves the rest of the config alone) */
  async sshAgentIntegrationEnable(): Promise<ApiResponse<SshIntegrationStatus>> {
    return invoke('ssh_agent_integration_enable');
  },


  /** One-click disable: removes the anchor block entirely */
  async sshAgentIntegrationDisable(): Promise<ApiResponse<SshIntegrationStatus>> {
    return invoke('ssh_agent_integration_disable');
  },


  /** Read-only analysis of the agent surface of ~/.ssh/config (Include expansion + SSH_AUTH_SOCK + socket probing) */
  async sshAgentConfigAnalysis(): Promise<ApiResponse<SshConfigAgentAnalysis>> {
    return invoke('ssh_agent_config_analysis');
  },


  async getSshKeys(): Promise<ApiResponse<SshAgentKey[]>> {
    return invoke('get_ssh_keys');
  },


  /** Previews an OpenSSH private key file (fingerprint / type / whether it is passphrase-protected) without storing it */
  async inspectSshKeyFile(path: string): Promise<ApiResponse<SshKeyInspection>> {
    return invoke('inspect_ssh_key_file', { path });
  },


  /** Imports an OpenSSH private key file into the database as an SshKey entry (snake_case key contract) */
  async importSshKey(request: {
    identity_id: string;
    path: string;
    name?: string;
    passphrase?: string;
  }): Promise<ApiResponse<SshKeyImported>> {
    return invoke('import_ssh_key', { request });
  },


  /** Generates an SSH keypair in the page and stores it (RSA 4096 can take tens of seconds, so the caller must show a loading state) */
  async generateSshKey(request: {
    identity_id: string;
    key_type: string;
    comment?: string;
    name?: string;
  }): Promise<ApiResponse<SshKeyGenerated>> {
    return invoke('generate_ssh_key', { request });
  },


  // -------------------------------------------------------------------------
  // SSH signing approvals
  // -------------------------------------------------------------------------

  async sshApprovalRespond(requestId: string, allow: boolean): Promise<ApiResponse<boolean>> {
    return invoke('ssh_approval_respond', { request: { request_id: requestId, allow } });
  },
};
