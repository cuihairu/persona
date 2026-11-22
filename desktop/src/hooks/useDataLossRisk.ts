import { useCallback, useEffect, useState } from 'react';
import { personaAPI } from '@/utils/api';

/** 数据丢失风险档位（设计稿 §6.5 / TODO S5-b）。
 * - `high`：已入同步组但仅本机一台设备、且从未导出过备份——「设备全丢=库全丢」
 * - `medium`：同上但已绑定账号（有账号找回路径，警示降一档）
 * - `none`：未入组（本地库本就不跨设备，不在此警示面管辖）/ 已有第二台
 *   设备 / 已导出过备份——警示自动解除 */
export type DataLossRiskLevel = 'none' | 'high' | 'medium';

export interface DataLossRisk {
  /** 任一状态源读取失败 → true（警示静默隐藏，不误报） */
  loading: boolean;
  /** 同步组已入组 */
  joined: boolean;
  /** 组内设备数（含本机；≤1 = 单设备高危） */
  deviceCount: number;
  /** 本机导出过加密备份（settings.backup 凭证在场） */
  hasBackup: boolean;
  /** 已绑定账号（账号模式警示降一档） */
  hasAccount: boolean;
  /** 跨设备同步偏好开关是否开启（settings.sync_methods；读取失败按安全侧
   * true——宁可少提示「可重新开启」，不误报）。**只读偏好，不决定档位**：
   * 数据是否在组内是 keyring 事实，不受偏好开关改写。 */
  crossDeviceSyncEnabled: boolean;
  level: DataLossRiskLevel;
  refresh: () => Promise<void>;
}

/** 纯函数：档位判定（测试锚点）。解除条件（TODO S5-b ③）：
 * 第二台设备到位或已导出备份 → none；账号绑定只降档不解除。 */
export function computeDataLossRisk(input: {
  joined: boolean;
  deviceCount: number;
  hasBackup: boolean;
  hasAccount: boolean;
}): DataLossRiskLevel {
  if (!input.joined) return 'none';
  if (input.deviceCount >= 2 || input.hasBackup) return 'none';
  return input.hasAccount ? 'medium' : 'high';
}

/** 数据丢失警示状态源：同步组状态 + 设备清单 + workspace settings
 * （backup 凭证 / 账号绑定）三路并行读取。任一路失败按安全侧降级
 * （未入组 → none），宁可少报不误报。 */
export function useDataLossRisk(): DataLossRisk {
  const [state, setState] = useState<Omit<DataLossRisk, 'refresh'>>({
    loading: true,
    joined: false,
    deviceCount: 0,
    hasBackup: false,
    hasAccount: false,
    crossDeviceSyncEnabled: true,
    level: 'none',
  });

  const refresh = useCallback(async (): Promise<void> => {
    try {
      const [statusResp, devicesResp, settingsResp] = await Promise.all([
        personaAPI.syncGroupStatus(),
        personaAPI.syncListDevices(),
        personaAPI.getWorkspaceSettings(),
      ]);
      const joined = Boolean(statusResp.success && statusResp.data);
      const deviceCount =
        devicesResp.success && devicesResp.data ? devicesResp.data.length : 0;
      const settings = settingsResp.success ? settingsResp.data : undefined;
      const hasBackup = Boolean(settings?.backup);
      const hasAccount = Boolean(settings?.account);
      // 偏好开关只读展示（不决定档位）；读取失败按安全侧 true（宁可少提示）
      const crossDeviceSyncEnabled = settings?.sync_methods?.cross_device_sync ?? true;
      setState({
        loading: false,
        joined,
        deviceCount,
        hasBackup,
        hasAccount,
        crossDeviceSyncEnabled,
        level: computeDataLossRisk({ joined, deviceCount, hasBackup, hasAccount }),
      });
    } catch {
      // 读取失败静默隐藏警示（同 SyncGroupSection 口径），不制造误报
      setState((prev) => ({ ...prev, loading: false, level: 'none' }));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { ...state, refresh };
}
