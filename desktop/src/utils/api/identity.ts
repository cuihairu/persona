import { invoke } from './invoke';

import type {
  ApiResponse,
  Identity,
  CreateIdentityRequest,
  UpdateIdentityRequest,
  TravelStatus,
  TravelCounts,
  IdentityExport,
} from '@/types';

export const identityApi = {

  async createIdentity(request: CreateIdentityRequest): Promise<ApiResponse<Identity>> {
    return invoke('create_identity', { request });
  },


  async updateIdentity(request: UpdateIdentityRequest): Promise<ApiResponse<Identity>> {
    return invoke('update_identity', { request });
  },


  async deleteIdentity(identityId: string): Promise<ApiResponse<boolean>> {
    return invoke('delete_identity', { identity_id: identityId });
  },


  async getIdentities(): Promise<ApiResponse<Identity[]>> {
    return invoke('get_identities');
  },


  async getIdentity(id: string): Promise<ApiResponse<Identity | null>> {
    return invoke('get_identity', { id });
  },


  async getActiveIdentity(): Promise<ApiResponse<string | null>> {
    return invoke('get_active_identity');
  },


  async setActiveIdentity(identityId: string): Promise<ApiResponse<boolean>> {
    return invoke('set_active_identity', { identity_id: identityId });
  },


  async clearActiveIdentity(): Promise<ApiResponse<boolean>> {
    return invoke('clear_active_identity');
  },


  // -------------------------------------------------------------------------
  // 导出 / 敏感字段 reveal / 重新认证
  // -------------------------------------------------------------------------

  async exportIdentity(identityId: string): Promise<ApiResponse<IdentityExport>> {
    return invoke('export_identity', { identity_id: identityId });
  },


  // ---------------------------------------------------------------------
  // 旅行模式（Travel Mode）
  // ---------------------------------------------------------------------

  /** 旅行模式状态（免解锁读取；inconsistent = active && !sidecar_exists） */
  async getTravelStatus(): Promise<ApiResponse<TravelStatus>> {
    return invoke('get_travel_status');
  },


  /** 窄写身份的 travel 标记位（enter 时随之移出本设备的身份清单） */
  async setTravelMarked(identityId: string, marked: boolean): Promise<ApiResponse<boolean>> {
    return invoke('set_travel_marked', { identityId, marked });
  },


  /** 进入旅行模式：被标记身份打包加密进 sidecar 并从主库删除 */
  async enterTravelMode(passphrase: string): Promise<ApiResponse<TravelCounts>> {
    return invoke('enter_travel_mode', { passphrase });
  },


  /** 退出旅行模式：输 travel 口令把被移除身份原样恢复回主库 */
  async exitTravelMode(passphrase: string): Promise<ApiResponse<TravelCounts>> {
    return invoke('exit_travel_mode', { passphrase });
  },
};
