import { invoke } from './invoke';

import type {
  ApiResponse,
  Statistics,
  AuditLogEntry,
  AuditQueryRequest,
  AuditStatistics,
  HealthReport,
  HealthScanRequest,
} from '@/types';

export const auditApi = {

  async getStatistics(): Promise<ApiResponse<Statistics>> {
    return invoke('get_statistics');
  },


  // -------------------------------------------------------------------------
  // 审计
  // -------------------------------------------------------------------------

  async auditQuery(request: AuditQueryRequest): Promise<ApiResponse<AuditLogEntry[]>> {
    return invoke('audit_query', { request });
  },


  async auditStatistics(): Promise<ApiResponse<AuditStatistics>> {
    return invoke('audit_statistics');
  },


  async auditCleanup(retainDays: number): Promise<ApiResponse<number>> {
    return invoke('audit_cleanup', { retain_days: retainDays });
  },


  // -------------------------------------------------------------------------
  // Watchtower 健康扫描
  // -------------------------------------------------------------------------

  async healthScan(request?: HealthScanRequest): Promise<ApiResponse<HealthReport>> {
    return invoke('health_scan', { request: request ?? {} });
  },
};
