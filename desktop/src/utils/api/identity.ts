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
  // Export / sensitive-field reveal / re-authentication
  // -------------------------------------------------------------------------

  async exportIdentity(identityId: string): Promise<ApiResponse<IdentityExport>> {
    return invoke('export_identity', { identity_id: identityId });
  },


  // ---------------------------------------------------------------------
  // Travel mode
  // ---------------------------------------------------------------------

  /** Travel mode status (read-only without unlocking; inconsistent = active && !sidecar_exists) */
  async getTravelStatus(): Promise<ApiResponse<TravelStatus>> {
    return invoke('get_travel_status');
  },


  /** Narrow write of an identity's travel-marked flag (on enter, the marked identity moves off this device's identity list) */
  async setTravelMarked(identityId: string, marked: boolean): Promise<ApiResponse<boolean>> {
    return invoke('set_travel_marked', { identityId, marked });
  },


  /** Enter travel mode: the marked identities are packed and encrypted into a sidecar and removed from the main database */
  async enterTravelMode(passphrase: string): Promise<ApiResponse<TravelCounts>> {
    return invoke('enter_travel_mode', { passphrase });
  },


  /** Exit travel mode: supply the travel passphrase to restore the removed identities into the main database verbatim */
  async exitTravelMode(passphrase: string): Promise<ApiResponse<TravelCounts>> {
    return invoke('exit_travel_mode', { passphrase });
  },
};
