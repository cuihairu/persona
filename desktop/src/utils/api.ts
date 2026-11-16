import { accountApi } from './api/account';
import { auditApi } from './api/audit';
import { backupApi } from './api/backup';
import { credentialApi } from './api/credential';
import { desktopApi } from './api/desktop';
import { identityApi } from './api/identity';
import { passkeyApi } from './api/passkey';
import { serviceApi } from './api/service';
import { sshApi } from './api/ssh';
import { syncApi } from './api/sync';
import { walletApi } from './api/wallet';

export const personaAPI = {
  ...accountApi,
  ...auditApi,
  ...backupApi,
  ...credentialApi,
  ...desktopApi,
  ...identityApi,
  ...passkeyApi,
  ...serviceApi,
  ...sshApi,
  ...syncApi,
  ...walletApi,
};

export { requestUnlockGate } from './api/invoke';
