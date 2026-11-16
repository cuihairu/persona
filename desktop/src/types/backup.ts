/** 备份域：证据、导出/恢复/推送产出、版本与远端删除。 */

/** 一次整库加密备份的导出记录（core `BackupEvidence` 镜像）。
 * 非敏感元数据；备份口令永不落盘。 */
export interface BackupEvidence {
  /** 导出时刻（RFC3339） */
  exported_at: string;
  /** 目标类型："file"（本地文件）/ "server"（服务器密文仓，后续批） */
  destination: string;
  /** 密文字节数 */
  size_bytes: number;
}

/** `backup_export_to_file` 的返回（含与 BackupEvidence 对账的元数据）。 */
export interface BackupExportOutcome {
  path: string;
  size_bytes: number;
  sha256: string;
  exported_at: string;
}

/** `backup_restore_from_file` 的返回：换库段留下的原库副本 `.bak` 路径
 * （原库不存在时为 null——全新安装上的首次恢复没有可留存的旧库）。 */
export interface BackupRestoreOutcome {
  backup_copy: string | null;
}

/** `backup_push_to_server` 的返回（服务器返回元数据 + 本地导出凭证时刻）。 */
export interface BackupPushOutcome {
  backup_id: string;
  device_name: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
  /** 同设备最新版本 sha256 相同时服务器去重（未产生新版本） */
  deduplicated: boolean;
  exported_at: string;
}

/** 服务器密文仓里的一个备份版本（列表视图）。 */
export interface BackupVersionView {
  backup_id: string;
  device_name: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
}

/** `backup_delete_server_version` 的返回（服务器 404 幂等，恒 true）。 */
export interface BackupServerDeleteOutcome {
  deleted: boolean;
}
