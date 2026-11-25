/** SSH domain: agent status and keys, approval requests, config parsing output. */

/** persona://ssh-approval event payload: an SSH signing request awaiting approval */
export interface SshApprovalRequest {
  request_id: string;
  /** Credential UUID (non-sensitive) */
  key_id: string;
  /** Public key fingerprint (first 8 bytes of SHA256, for manual verification) */
  fingerprint: string;
  /** Operation name (currently always "sign") */
  operation: string;
  /** Target host (null when unknown) */
  peer: string | null;
  /** Trigger reason (explains the policy) */
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
  /** Wire-format algorithm (ssh-ed25519 etc.); null when the data is unavailable */
  ssh_algorithm?: string | null;
  /** SHA256 fingerprint (SHA256:…), same convention as the import/generate confirmation */
  fingerprint?: string | null;
  /** Bit length / curve label (Ed25519→256, RSA→4096, ECDSA→P-256); null when not applicable */
  key_size?: string | null;
  /** Full public key line, for one-click copy */
  public_key?: string | null;
}

/** inspect_ssh_key_file response: shown in the import confirmation dialog (fingerprint verified manually) */
export interface SshKeyInspection {
  file_name: string;
  key_type: string;
  ssh_algorithm: string;
  public_key: string;
  fingerprint: string;
  comment: string;
  encrypted: boolean;
}

/** import_ssh_key response */
export interface SshKeyImported {
  credential_id: string;
  name: string;
  key_type: string;
  public_key: string;
  fingerprint: string;
}

/** generate_ssh_key response: same shape as import (reused by the success view) */
export interface SshKeyGenerated {
  credential_id: string;
  name: string;
  key_type: string;
  public_key: string;
  fingerprint: string;
}

export interface SshIntegrationStatus {
  /** The anchor block exists and points at the current agent socket */
  enabled: boolean;
  /** The anchor block exists but points elsewhere (old path / hand-edited) — re-enabling fixes it */
  anomaly: string | null;
  /** A persona IdentityAgent written by hand outside the anchor block (shown as a hint, never touched automatically) */
  manualEntry: boolean;
  /** Actual path of ~/.ssh/config */
  configPath: string;
  /** Stable agent socket (the value written / the comparison baseline) */
  socketPath: string;
  /** Current IdentityAgent value of the anchor block (null when not enabled) */
  identityAgent: string | null;
  /** OpenSSH version (null if detection failed; IdentityAgent needs 8.3+) */
  sshVersion: string | null;
  /** The config file exists on disk (absence is not an error: first enable creates it) */
  configExists: boolean;
  /** Why reading failed (permissions/IO) — shown as-is, never silently swallowed; enable refuses to write */
  readError: string | null;
}

/** One agent-related entry in ~/.ssh/config (mirrors Rust SshConfigEntry) */
export interface SshConfigEntry {
  /** Absolute path of the containing file (may be a different file after Include expansion) */
  file: string;
  /** Line number (1-based) */
  line: number;
  /** Raw scope line (empty string = top-level global; otherwise a Host/Match line) */
  scope: string;
  /** Raw keyword (case preserved) */
  keyword: string;
  /** Value (quotes stripped) */
  value: string;
}

/** `ssh_agent_config_analysis` return (mirrors Rust SshConfigAgentAnalysis):
 *  read-only analysis of the agent surface of ~/.ssh/config — Include expansion
 *  + environment variables + socket probing */
export interface SshConfigAgentAnalysis {
  configPath: string;
  /** The config file exists on disk */
  configExists: boolean;
  /** The main file is readable (read failures on Included sub-files only land in warnings) */
  readable: boolean;
  /** Why the main file read failed (permissions/IO/non-UTF-8) */
  readError: string | null;
  /** Non-fatal problems found while parsing (missing Include file, loop, excessive depth, etc.) */
  warnings: string[];
  /** Agent-related entries (IdentityAgent/ForwardAgent/AddKeysToAgent/ProxyAgent;
   *  entries inside the persona anchor block are not counted) */
  entries: SshConfigEntry[];
  /** ForwardAgent entries (forwarding is often shown separately) */
  forwardAgentEntries: SshConfigEntry[];
  /** Effective IdentityAgent: the first top-level entry wins (ssh is first-wins;
   *  a block at EOF is overridden by an earlier user global entry); when no user
   *  global entry exists, the persona anchor block value is used; null when
   *  neither exists — no guessing */
  identityAgentEffective: string | null;
  /** Environment SSH_AUTH_SOCK */
  sshAuthSock: string | null;
  /** Effective socket: identityAgentEffective first, falling back to SSH_AUTH_SOCK */
  effectiveSocket: string | null;
  /** Reachability probe of effectiveSocket: true = a process is listening / false = nothing listening / null = unknown */
  socketAlive: boolean | null;
  /** Reachability probe of the persona agent's stable socket (whether the agent process is alive) */
  personaSocketAlive: boolean;
}
