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


  /** ~/.ssh/config IdentityAgent 锚点块三态检测（纯读，不解锁） */
  async sshAgentIntegrationStatus(): Promise<ApiResponse<SshIntegrationStatus>> {
    return invoke('ssh_agent_integration_status');
  },


  /** 一键启用：幂等 upsert 锚点块（只动块内，其余配置不碰） */
  async sshAgentIntegrationEnable(): Promise<ApiResponse<SshIntegrationStatus>> {
    return invoke('ssh_agent_integration_enable');
  },


  /** 一键停用：整块移除锚点块 */
  async sshAgentIntegrationDisable(): Promise<ApiResponse<SshIntegrationStatus>> {
    return invoke('ssh_agent_integration_disable');
  },


  /** ~/.ssh/config 的 agent 面只读分析（Include 展开 + SSH_AUTH_SOCK + socket 探测） */
  async sshAgentConfigAnalysis(): Promise<ApiResponse<SshConfigAgentAnalysis>> {
    return invoke('ssh_agent_config_analysis');
  },


  async getSshKeys(): Promise<ApiResponse<SshAgentKey[]>> {
    return invoke('get_ssh_keys');
  },


  /** 预览 OpenSSH 私钥文件（指纹/类型/是否受保护），不入库 */
  async inspectSshKeyFile(path: string): Promise<ApiResponse<SshKeyInspection>> {
    return invoke('inspect_ssh_key_file', { path });
  },


  /** 导入 OpenSSH 私钥文件入库为 SshKey 条目（snake_case 键契约） */
  async importSshKey(request: {
    identity_id: string;
    path: string;
    name?: string;
    passphrase?: string;
  }): Promise<ApiResponse<SshKeyImported>> {
    return invoke('import_ssh_key', { request });
  },


  /** 页面内生成 SSH 密钥对并入库（RSA 4096 可能数十秒，调用方须有加载态） */
  async generateSshKey(request: {
    identity_id: string;
    key_type: string;
    comment?: string;
    name?: string;
  }): Promise<ApiResponse<SshKeyGenerated>> {
    return invoke('generate_ssh_key', { request });
  },


  // -------------------------------------------------------------------------
  // SSH 签名审批
  // -------------------------------------------------------------------------

  async sshApprovalRespond(requestId: string, allow: boolean): Promise<ApiResponse<boolean>> {
    return invoke('ssh_approval_respond', { request: { request_id: requestId, allow } });
  },
};
