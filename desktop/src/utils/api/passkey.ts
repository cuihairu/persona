import { invoke } from './invoke';

import type {
  ApiResponse,
  Passkey,
  CreatePasskeyRequest,
  PasskeyCreationResponse,
} from '@/types';

export const passkeyApi = {

  // -------------------------------------------------------------------------
  // Passkey
  // -------------------------------------------------------------------------

  async passkeyList(identityId: string): Promise<ApiResponse<Passkey[]>> {
    return invoke('passkey_list', { identity_id: identityId });
  },


  async passkeyListByRp(rpId: string): Promise<ApiResponse<Passkey[]>> {
    return invoke('passkey_list_by_rp', { rp_id: rpId });
  },


  async passkeyGet(id: string): Promise<ApiResponse<Passkey | null>> {
    return invoke('passkey_get', { id });
  },


  async passkeyDelete(id: string): Promise<ApiResponse<boolean>> {
    return invoke('passkey_delete', { id });
  },


  async passkeyCreate(request: CreatePasskeyRequest): Promise<ApiResponse<PasskeyCreationResponse>> {
    return invoke('passkey_create', { request });
  },


  async passkeySelfTest(id: string): Promise<ApiResponse<boolean>> {
    return invoke('passkey_self_test', { id });
  },


  async passkeyExportPrivateKey(id: string): Promise<ApiResponse<string>> {
    return invoke('passkey_export_private_key', { id });
  },


  // -------------------------------------------------------------------------
  // Passkey approvals (create/assert requests forwarded by the bridge over a Unix socket)
  // -------------------------------------------------------------------------

  async passkeyApprovalRespond(requestId: string, allow: boolean): Promise<ApiResponse<boolean>> {
    return invoke('passkey_approval_respond', { request: { request_id: requestId, allow } });
  },
};
