import { invoke } from './invoke';

import type {
  ApiResponse,
  BackupExportOutcome,
  BackupRestoreOutcome,
  BackupPushOutcome,
  BackupVersionView,
  BackupServerDeleteOutcome,
} from '@/types';

export const backupApi = {

  /** 整库加密备份导出到本地文件（S5 自救口）：口令加密、主库不解密。
   * 成功后 settings.backup 落导出凭证（服务端真相在返回的 outcome）。 */
  async backupExportToFile(
    path: string,
    passphrase: string,
  ): Promise<ApiResponse<BackupExportOutcome>> {
    return invoke('backup_export_to_file', { request: { path, passphrase } });
  },


  /** 从本地备份文件恢复整库（S5 自救口第二批，与 CLI `restore --file` 同语义）。
   * 口令错/文件坏在 staged 复验阶段就报错——现有库与会话都不受影响；换库成功后
   * 后端 service 被取下，调用方须随后 `checkServiceStatus` 驱动回解锁屏
   * （恢复出的库主密码可能与当前会话不同）。 */
  async backupRestoreFromFile(
    path: string,
    passphrase: string,
  ): Promise<ApiResponse<BackupRestoreOutcome>> {
    return invoke('backup_restore_from_file', { request: { path, passphrase } });
  },


  /** 整库加密备份推送到服务器密文仓（S5-d）。快照加密在本地完成后才出网，
   * 口令与主密码不出本机；成功后 settings.backup 落 destination=server 凭证。 */
  async backupPushToServer(
    passphrase: string,
  ): Promise<ApiResponse<BackupPushOutcome>> {
    return invoke('backup_push_to_server', { request: { passphrase } });
  },


  /** 列出服务器密文仓的备份版本（倒序）。免解锁——锁屏救库也要能先看清单。 */
  async backupListServerVersions(
    limit?: number,
  ): Promise<ApiResponse<BackupVersionView[]>> {
    return invoke('backup_list_server_versions', {
      request: { limit: limit ?? null },
    });
  },


  /** 从服务器密文仓恢复整库。免解锁（锁屏救库同文件恢复口径）；换库成功后
   * 后端 service 被取下，调用方须随后 `checkServiceStatus` 驱动回解锁屏。 */
  async backupRestoreFromServer(
    backupId: string,
    passphrase: string,
  ): Promise<ApiResponse<BackupRestoreOutcome>> {
    return invoke('backup_restore_from_server', {
      request: { backup_id: backupId, passphrase },
    });
  },


  /** 删除服务器上的备份版本（幂等：已删除视为成功）。 */
  async backupDeleteServerVersion(
    backupId: string,
  ): Promise<ApiResponse<BackupServerDeleteOutcome>> {
    return invoke('backup_delete_server_version', {
      request: { backup_id: backupId },
    });
  },
};
