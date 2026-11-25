/** Health and audit domain: audit log/query/statistics, health report and scan requests. */

/** Audit log entry (read-only view, no sensitive payloads) */
export interface AuditLogEntry {
  id: string;
  user_id?: string;
  identity_id?: string;
  credential_id?: string;
  session_id?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  success: boolean;
  error_message?: string;
  metadata: Record<string, string>;
  timestamp: string;
}

/** Audit query filter (a None field = do not filter on it) */
export interface AuditQueryRequest {
  user_id?: string;
  identity_id?: string;
  action?: string;
  failures_only?: boolean;
  security_sensitive_only?: boolean;
  time_range?: [string, string];
  limit?: number;
}

export interface AuditStatistics {
  total_logs: number;
  failed_operations: number;
  recent_login_attempts: number;
  active_users_last_week: number;
}

// -------------------------------------------------------------------------
// Watchtower health scan (the report carries metadata only, never ciphertext)
// -------------------------------------------------------------------------

export type HealthSeverity = 'low' | 'medium' | 'high';

/** Issue kind (serde tag = "type", snake_case variant names) */
export interface HealthIssueKindPayload {
  type:
    | 'weak_password'
    | 'reused_password'
    | 'breached_password'
    | 'expired'
    | 'expiring_soon'
    | 'stale_unchanged'
    | 'two_factor_available';
  /** weak_password: zxcvbn score */
  score?: number;
  /** reused_password: number of credentials sharing the same plaintext password */
  group_size?: number;
  /** breached_password: number of appearances in the breach corpus */
  count?: number;
  /** expiring_soon / stale_unchanged: days until expiry / since last update */
  days?: number;
  /** two_factor_available: site matching the 2FA directory (normalized domain) */
  site?: string;
}

export interface HealthIssue {
  credential_id: string;
  credential_name: string;
  credential_type: string;
  severity: HealthSeverity;
  detail: string;
  /** serde(flatten)-flattened issue kind payload */
  type: HealthIssueKindPayload['type'];
  score?: number;
  group_size?: number;
  count?: number;
  days?: number;
  /** two_factor_available: site matching the 2FA directory (normalized domain) */
  site?: string;
}

export interface HealthReport {
  scanned_at: string;
  total_credentials: number;
  issues: HealthIssue[];
  /** Severity → count ("high"/"medium"/"low") */
  counts: Record<string, number>;
}

export interface HealthScanRequest {
  /** zxcvbn score threshold (0-4); below it the password is judged weak. Defaults to the core value when absent */
  min_password_score?: number;
  /** Expiry warning window (days) */
  expiry_warning_days?: number;
  /** Stale when not updated for more than this many days */
  stale_after_days?: number;
  /** Query the HIBP breach corpus (k-anonymity; only the first 5 hash characters are sent) */
  check_breaches?: boolean;
}
