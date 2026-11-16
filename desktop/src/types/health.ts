/** 健康与审计域：审计日志/查询/统计、健康报告与扫描请求。 */

/** 审计日志条目（只读视图，不含敏感负载） */
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

/** 审计查询过滤（None 字段 = 不过滤） */
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
// Watchtower 健康扫描（报告只含元数据，永不含密文）
// -------------------------------------------------------------------------

export type HealthSeverity = 'low' | 'medium' | 'high';

/** 问题类型（serde tag = "type"，snake_case 变体名） */
export interface HealthIssueKindPayload {
  type:
    | 'weak_password'
    | 'reused_password'
    | 'breached_password'
    | 'expired'
    | 'expiring_soon'
    | 'stale_unchanged'
    | 'two_factor_available';
  /** weak_password：zxcvbn 分数 */
  score?: number;
  /** reused_password：共用同一明文密码的凭据数 */
  group_size?: number;
  /** breached_password：在泄露库中出现的次数 */
  count?: number;
  /** expiring_soon / stale_unchanged：距过期/未更新天数 */
  days?: number;
  /** two_factor_available：命中 2FA 目录的站点（归一化域名） */
  site?: string;
}

export interface HealthIssue {
  credential_id: string;
  credential_name: string;
  credential_type: string;
  severity: HealthSeverity;
  detail: string;
  /** serde(flatten) 的问题类型负载 */
  type: HealthIssueKindPayload['type'];
  score?: number;
  group_size?: number;
  count?: number;
  days?: number;
  /** two_factor_available：命中 2FA 目录的站点（归一化域名） */
  site?: string;
}

export interface HealthReport {
  scanned_at: string;
  total_credentials: number;
  issues: HealthIssue[];
  /** 严重度 → 数量（"high"/"medium"/"low"） */
  counts: Record<string, number>;
}

export interface HealthScanRequest {
  /** zxcvbn 分数阈值（0-4），低于该值判弱；缺省用 core 默认值 */
  min_password_score?: number;
  /** 过期警告窗口（天） */
  expiry_warning_days?: number;
  /** 超过该天数未更新判陈旧 */
  stale_after_days?: number;
  /** 查询 HIBP 泄露库（k-anonymity，仅发送哈希前 5 字符） */
  check_breaches?: boolean;
}
