/** SSH 域：agent 状态与密钥、审批请求、config 解析产出。 */

/** persona://ssh-approval 事件负载：待审批的 SSH 签名请求 */
export interface SshApprovalRequest {
  request_id: string;
  /** 凭据 UUID（非敏感） */
  key_id: string;
  /** 公钥指纹（SHA256 前 8 字节，用于人工核对） */
  fingerprint: string;
  /** 操作名（当前恒为 "sign"） */
  operation: string;
  /** 目标主机（未知时为 null） */
  peer: string | null;
  /** 触发原因（策略说明） */
  reason: string;
}

export interface SshAgentStatus {
  running: boolean;
  socket_path?: string;
  pid?: number;
  key_count?: number;
  state_dir: string;
}

export interface SshAgentKey {
  id: string;
  identity_id: string;
  identity_name: string;
  name: string;
  tags: string[];
  created_at: string;
  updated_at: string;
  /** 线格式算法（ssh-ed25519 等）；数据取不到时为 null */
  ssh_algorithm?: string | null;
  /** SHA256 指纹（SHA256:…），与导入/生成确认处同口径 */
  fingerprint?: string | null;
  /** 位数/曲线标签（Ed25519→256、RSA→4096、ECDSA→P-256）；不适用为 null */
  key_size?: string | null;
  /** 完整公钥行，供一键复制 */
  public_key?: string | null;
}

/** inspect_ssh_key_file 响应：导入确认弹框展示（指纹人工核对） */
export interface SshKeyInspection {
  file_name: string;
  key_type: string;
  ssh_algorithm: string;
  public_key: string;
  fingerprint: string;
  comment: string;
  encrypted: boolean;
}

/** import_ssh_key 响应 */
export interface SshKeyImported {
  credential_id: string;
  name: string;
  key_type: string;
  public_key: string;
  fingerprint: string;
}

/** generate_ssh_key 响应：与导入同形（成功态展示复用） */
export interface SshKeyGenerated {
  credential_id: string;
  name: string;
  key_type: string;
  public_key: string;
  fingerprint: string;
}

export interface SshIntegrationStatus {
  /** 锚点块存在且指向当前 agent socket */
  enabled: boolean;
  /** 锚点块存在但指向别处（旧路径/手改）——重新启用即修复 */
  anomaly: string | null;
  /** 锚点块之外用户手写的 persona IdentityAgent（提示，不自动动它） */
  manualEntry: boolean;
  /** ~/.ssh/config 实际路径 */
  configPath: string;
  /** agent 稳定 socket（写入值/比对基准） */
  socketPath: string;
  /** 锚点块当前 IdentityAgent 值（未启用 null） */
  identityAgent: string | null;
  /** OpenSSH 版本（探测失败 null；IdentityAgent 需 8.3+） */
  sshVersion: string | null;
  /** config 文件在盘上（不存在不算错误：首次启用会创建） */
  configExists: boolean;
  /** 读失败原因（权限/IO）——如实显示，绝不静默吞；enable 时会拒绝写 */
  readError: string | null;
}

/** ~/.ssh/config 里的单条 agent 相关配置（对应 Rust SshConfigEntry） */
export interface SshConfigEntry {
  /** 所在文件绝对路径（Include 展开后可能是别的文件） */
  file: string;
  /** 行号（1 起） */
  line: number;
  /** 作用域行原文（空串 = 顶层全局；否则 Host/Match 行） */
  scope: string;
  /** 关键字原文（保留大小写） */
  keyword: string;
  /** 值（去引号） */
  value: string;
}

/** `ssh_agent_config_analysis` 返回（对应 Rust SshConfigAgentAnalysis）：
 *  ~/.ssh/config 的 agent 面只读分析——Include 展开 + 环境变量 + socket 探测 */
export interface SshConfigAgentAnalysis {
  configPath: string;
  /** config 文件在盘上 */
  configExists: boolean;
  /** 主文件可读（Include 子文件读失败只进 warnings） */
  readable: boolean;
  /** 主文件读失败原因（权限/IO/非 UTF-8） */
  readError: string | null;
  /** 解析过程中的非致命问题（Include 缺文件/循环/超深度等） */
  warnings: string[];
  /** agent 相关条目（IdentityAgent/ForwardAgent/AddKeysToAgent/ProxyAgent；
   *  persona 锚点块内不计） */
  entries: SshConfigEntry[];
  /** ForwardAgent 条目（转发经常单列展示） */
  forwardAgentEntries: SshConfigEntry[];
  /** 生效 IdentityAgent：首个顶层条目优先（ssh first-wins，块在 EOF 被
   *  更早的用户全局条目压过）；无用户全局条目时取 persona 锚点块值；
   *  两者皆无时 null 不妄断 */
  identityAgentEffective: string | null;
  /** 环境 SSH_AUTH_SOCK */
  sshAuthSock: string | null;
  /** 生效 socket：identityAgentEffective 优先，否则退 SSH_AUTH_SOCK */
  effectiveSocket: string | null;
  /** effectiveSocket 连通探测：true 有进程在听 / false 无人听 / null 未知 */
  socketAlive: boolean | null;
  /** persona agent 稳定 socket 连通探测（agent 进程是否活着） */
  personaSocketAlive: boolean;
}
