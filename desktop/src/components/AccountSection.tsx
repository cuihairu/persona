import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '../utils/api';
import DataScopeConsentModal from './DataScopeConsentModal';
import type { AccountBinding, AccountDeviceInfo } from '../types';

/**
 * Account settings section (M2 UI batch): registration / password login wizard for the
 * persona-server account, plus device management, recovery codes and sign-out in the
 * bound state. Privacy red line unchanged: unbound by default; binding is an
 * explicit action. Token truth lives in the OS keyring the whole time (written
 * directly by the command layer); the frontend only sees non-sensitive metadata
 * such as expiry / fingerprint.
 *
 * Wizard order (register): accountRegister (yields account_id — the server has
 * no username→id resolution endpoint, so account_id is the sole login identifier) →
 * accountSrpRegisterWithPassword (SRP credentials; sets up Bearer command-layer
 * resolution) → accountSrpLogin (challenge/M1/M2 verification in core; the 15min
 * token goes into the keyring) → accountExchangeSession (exchange for a 24h
 * session, into the keyring) → accountSetBinding.
 * The login path shares the last three steps (account_id filled in by the user).
 *
 * Privacy red line (same policy as M4): submit actions (register/login) first put
 * the account data-exposure surface in front of DataScopeConsentModal (the account
 * disclosure: what the server will and will never see); only confirmation runs the
 * orchestration; cancel / Esc / clicking the backdrop never passes through. One
 * disclosure covers the local account capability surface; re-login / device
 * management after binding does not re-prompt. Mounting the component makes zero
 * network requests (reads local settings only).
 */

type WizardMode = 'register' | 'login';

const AccountSection: React.FC = () => {
  const { t } = useTranslation();
  const [binding, setBinding] = useState<AccountBinding | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Wizard form
  const [mode, setMode] = useState<WizardMode>('register');
  const [username, setUsername] = useState('');
  const [accountId, setAccountId] = useState('');
  const [password, setPassword] = useState('');
  const [deviceName, setDeviceName] = useState('');

  // Bound state
  const [loginPassword, setLoginPassword] = useState('');
  const [devices, setDevices] = useState<AccountDeviceInfo[] | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  // Disclosure firewall: None = no pending action; Some = awaiting the user's
  // explicit confirmation of the disclosure surface
  const [consentPending, setConsentPending] = useState<'register' | 'login' | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const resp = await personaAPI.getWorkspaceSettings();
      if (cancelled) return;
      if (resp.success && resp.data) {
        setBinding(resp.data.account ?? null);
      } else {
        setLoadFailed(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const fail = useCallback((message?: string) => {
    setError(message ?? null);
  }, []);

  /** Sign-in orchestration: SRP login → exchange for a 24h session (the token stays in the command-layer keyring throughout) */
  const signIn = useCallback(
    async (id: string, pw: string, device: string): Promise<boolean> => {
      const login = await personaAPI.accountSrpLogin(id, {
        device_name: device,
        password: pw,
      });
      if (!login.success) {
        fail(login.error);
        return false;
      }
      const exchange = await personaAPI.accountExchangeSession(id);
      if (!exchange.success) {
        fail(exchange.error);
        return false;
      }
      return true;
    },
    [fail]
  );

  const registerExecute = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const reg = await personaAPI.accountRegister({ username: username.trim() });
      if (!reg.success || !reg.data) {
        fail(reg.error);
        return;
      }
      const id = reg.data.account_id;
      const srpReg = await personaAPI.accountSrpRegisterWithPassword(id, {
        device_name: deviceName.trim(),
        password,
      });
      if (!srpReg.success) {
        fail(srpReg.error);
        return;
      }
      if (!(await signIn(id, password, deviceName.trim()))) return;
      const bind = await personaAPI.accountSetBinding({
        account_id: id,
        username: username.trim(),
        device_name: deviceName.trim(),
      });
      if (!bind.success || !bind.data) {
        fail(bind.error);
        return;
      }
      setBinding(bind.data.account ?? null);
      setPassword('');
    } finally {
      setBusy(false);
    }
  }, [username, password, deviceName, signIn, fail, t]);

  const loginExistingExecute = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const id = accountId.trim();
      if (!(await signIn(id, password, deviceName.trim()))) return;
      // The login path cannot get the username (no resolution endpoint) — the
      // display slot uses account_id for now; the username can be viewed on the
      // registering device
      const bind = await personaAPI.accountSetBinding({
        account_id: id,
        username: id,
        device_name: deviceName.trim(),
      });
      if (!bind.success || !bind.data) {
        fail(bind.error);
        return;
      }
      setBinding(bind.data.account ?? null);
      setPassword('');
      setLoginPassword('');
    } finally {
      setBusy(false);
    }
  }, [accountId, password, deviceName, signIn, fail, t]);

  const relogin = useCallback(async () => {
    if (!binding || !loginPassword) {
      fail(t('settings.account.formIncomplete'));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (!(await signIn(binding.account_id, loginPassword, binding.device_name ?? ''))) return;
      setLoginPassword('');
      setNotice(t('settings.account.signedIn'));
    } finally {
      setBusy(false);
    }
  }, [binding, loginPassword, signIn, fail, t]);

  const loadDevices = useCallback(async () => {
    if (!binding) return;
    setBusy(true);
    setError(null);
    try {
      const resp = await personaAPI.accountListDevices(binding.account_id);
      if (!resp.success || !resp.data) {
        fail(resp.error);
        return;
      }
      setDevices(resp.data.devices);
    } finally {
      setBusy(false);
    }
  }, [binding, fail]);

  const revokeDevice = useCallback(
    async (deviceId: string) => {
      if (!binding) return;
      setBusy(true);
      setError(null);
      try {
        const resp = await personaAPI.accountRevokeDevice(binding.account_id, deviceId);
        if (!resp.success) {
          fail(resp.error);
          return;
        }
        setDevices((prev) => prev?.filter((d) => d.device_id !== deviceId) ?? null);
      } finally {
        setBusy(false);
      }
    },
    [binding, fail]
  );

  const generateRecovery = useCallback(async () => {
    if (!binding) return;
    setBusy(true);
    setError(null);
    try {
      const resp = await personaAPI.accountGenerateRecoveryCodes(binding.account_id);
      if (!resp.success || !resp.data) {
        fail(resp.error);
        return;
      }
      setRecoveryCodes(resp.data.codes);
    } finally {
      setBusy(false);
    }
  }, [binding, fail]);

  const consentConfirm = useCallback(() => {
    setConsentPending(null);
    if (consentPending === 'register') {
      void registerExecute();
    } else if (consentPending === 'login') {
      void loginExistingExecute();
    }
  }, [consentPending, registerExecute, loginExistingExecute]);

  const consentCancel = useCallback(() => {
    setConsentPending(null);
  }, []);

  const signOut = useCallback(async () => {
    if (!binding) return;
    setBusy(true);
    setError(null);
    try {
      const resp = await personaAPI.accountSignOut(binding.account_id);
      if (!resp.success) {
        fail(resp.error);
        return;
      }
      const bind = await personaAPI.accountSetBinding(null);
      if (!bind.success || !bind.data) {
        fail(bind.error);
        return;
      }
      setBinding(null);
      setDevices(null);
      setRecoveryCodes(null);
      setNotice(t('settings.account.signedOut'));
    } finally {
      setBusy(false);
    }
  }, [binding, fail, t]);

  if (loadFailed) {
    return (
      <div data-testid="account-section">
        <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">
          {t('settings.account.title')}
        </h3>
        <p className="mt-2 text-xs text-red-600 dark:text-red-400" data-testid="account-load-error">
          {t('settings.account.loadFailed')}
        </p>
      </div>
    );
  }

  return (
    <div data-testid="account-section">
      <div className="flex items-center justify-between gap-4 mb-2">
        <div className="min-w-0">
          <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">
            {t('settings.account.title')}
          </h3>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {t('settings.account.description')}
          </p>
        </div>
      </div>

      {error && (
        <p className="mt-2 text-xs text-red-600 dark:text-red-400" data-testid="account-error">
          {error}
        </p>
      )}
      {notice && (
        <p className="mt-2 text-xs text-green-600 dark:text-green-400" data-testid="account-notice">
          {notice}
        </p>
      )}

      {!binding ? (
        <div className="mt-3 space-y-3" data-testid="account-wizard">
          <div className="flex gap-2" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'register'}
              onClick={() => {
                setMode('register');
                setError(null);
              }}
              className={mode === 'register' ? 'btn-primary' : 'btn-secondary'}
            >
              {t('settings.account.modeRegister')}
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'login'}
              onClick={() => {
                setMode('login');
                setError(null);
              }}
              className={mode === 'login' ? 'btn-primary' : 'btn-secondary'}
            >
              {t('settings.account.modeLogin')}
            </button>
          </div>

          {mode === 'register' ? (
            <div className="space-y-2" data-testid="account-register-form">
              <label className="block text-xs text-gray-600 dark:text-gray-400">
                {t('settings.account.usernameLabel')}
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder={t('settings.account.usernamePlaceholder')}
                  className="mt-1 w-full input"
                  data-testid="account-username-input"
                />
              </label>
              <label className="block text-xs text-gray-600 dark:text-gray-400">
                {t('settings.account.passwordLabel')}
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t('settings.account.passwordPlaceholder')}
                  className="mt-1 w-full input"
                  data-testid="account-password-input"
                />
              </label>
              <label className="block text-xs text-gray-600 dark:text-gray-400">
                {t('settings.account.deviceNameLabel')}
                <input
                  type="text"
                  value={deviceName}
                  onChange={(e) => setDeviceName(e.target.value)}
                  placeholder={t('settings.account.deviceNamePlaceholder')}
                  className="mt-1 w-full input"
                  data-testid="account-device-name-input"
                />
              </label>
              <button
                type="button"
                onClick={() => {
                  if (!username.trim() || !password || !deviceName.trim()) {
                    fail(t('settings.account.formIncomplete'));
                    return;
                  }
                  setConsentPending('register');
                }}
                disabled={busy}
                className="btn-primary"
                data-testid="account-register-submit"
              >
                {busy ? t('settings.account.busy') : t('settings.account.registerSubmit')}
              </button>
            </div>
          ) : (
            <div className="space-y-2" data-testid="account-login-form">
              <label className="block text-xs text-gray-600 dark:text-gray-400">
                {t('settings.account.accountIdLabel')}
                <input
                  type="text"
                  value={accountId}
                  onChange={(e) => setAccountId(e.target.value)}
                  placeholder={t('settings.account.accountIdPlaceholder')}
                  className="mt-1 w-full input"
                  data-testid="account-id-input"
                />
              </label>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {t('settings.account.accountIdHint')}
              </p>
              <label className="block text-xs text-gray-600 dark:text-gray-400">
                {t('settings.account.passwordLabel')}
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="mt-1 w-full input"
                  data-testid="account-login-password-input"
                />
              </label>
              <label className="block text-xs text-gray-600 dark:text-gray-400">
                {t('settings.account.deviceNameLabel')}
                <input
                  type="text"
                  value={deviceName}
                  onChange={(e) => setDeviceName(e.target.value)}
                  placeholder={t('settings.account.deviceNamePlaceholder')}
                  className="mt-1 w-full input"
                  data-testid="account-login-device-name-input"
                />
              </label>
              <button
                type="button"
                onClick={() => {
                  if (!accountId.trim() || !password || !deviceName.trim()) {
                    fail(t('settings.account.formIncomplete'));
                    return;
                  }
                  setConsentPending('login');
                }}
                disabled={busy}
                className="btn-primary"
                data-testid="account-login-submit"
              >
                {busy ? t('settings.account.busy') : t('settings.account.loginSubmit')}
              </button>
            </div>
          )}
        </div>
      ) : (
        <div className="mt-3 space-y-3" data-testid="account-bound">
          <div className="flex items-center justify-between gap-4 text-sm">
            <span className="text-gray-700 dark:text-gray-300">
              {t('settings.account.boundAs', { username: binding.username })}
            </span>
            <button
              type="button"
              onClick={signOut}
              disabled={busy}
              className="btn-secondary"
              data-testid="account-sign-out"
            >
              {t('settings.account.signOut')}
            </button>
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {t('settings.account.accountId')}: <code>{binding.account_id}</code>
            {binding.device_name ? ` · ${t('settings.account.device')}: ${binding.device_name}` : ''}
          </p>

          <div className="flex items-center gap-2">
            <input
              type="password"
              value={loginPassword}
              onChange={(e) => setLoginPassword(e.target.value)}
              placeholder={t('settings.account.passwordPlaceholder')}
              className="input flex-1"
              data-testid="account-relogin-password"
            />
            <button
              type="button"
              onClick={relogin}
              disabled={busy || !loginPassword}
              className="btn-primary"
              data-testid="account-relogin-submit"
            >
              {t('settings.account.signIn')}
            </button>
          </div>

          <div className="flex flex-shrink-0 gap-2">
            <button
              type="button"
              onClick={loadDevices}
              disabled={busy}
              className="btn-secondary"
              data-testid="account-devices-button"
            >
              {t('settings.account.devices')}
            </button>
            <button
              type="button"
              onClick={generateRecovery}
              disabled={busy}
              className="btn-secondary"
              data-testid="account-recovery-button"
            >
              {t('settings.account.recoveryGenerate')}
            </button>
          </div>

          {devices && (
            <ul className="space-y-1" data-testid="account-devices-list">
              {devices.length === 0 && (
                <li className="text-xs text-gray-500 dark:text-gray-400">
                  {t('settings.account.devicesEmpty')}
                </li>
              )}
              {devices.map((device) => (
                <li
                  key={device.device_id}
                  className="flex items-center justify-between gap-2 text-xs"
                >
                  <span className="text-gray-700 dark:text-gray-300">
                    {device.device_name}
                    {device.status ? ` · ${device.status}` : ''}
                  </span>
                  <button
                    type="button"
                    onClick={() => revokeDevice(device.device_id)}
                    disabled={busy}
                    className="btn-secondary"
                    data-testid={`account-revoke-device-${device.device_id}`}
                  >
                    {t('settings.account.revokeDevice')}
                  </button>
                </li>
              ))}
            </ul>
          )}

          {recoveryCodes && (
            <div className="space-y-1" data-testid="account-recovery-codes">
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {t('settings.account.recoveryHint')}
              </p>
              <ul className="font-mono text-xs text-gray-800 dark:text-gray-200">
                {recoveryCodes.map((code) => (
                  <li key={code}>{code}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {consentPending && (
        <DataScopeConsentModal
          scope="account"
          onConfirm={consentConfirm}
          onCancel={consentCancel}
        />
      )}
    </div>
  );
};

export default AccountSection;
