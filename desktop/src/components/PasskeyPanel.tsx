import React, { useCallback, useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import {
  ArrowPathIcon,
  DocumentDuplicateIcon,
  FingerPrintIcon,
  ShieldExclamationIcon,
  TrashIcon,
} from '@heroicons/react/24/outline';
import { personaAPI } from '@/utils/api';
import { copyWithAutoClear } from '@/utils/clipboard';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useReauth } from '@/hooks/useReauth';
import ReauthModal from '@/components/ReauthModal';
import type { Passkey } from '@/types';

/** 表格行：passkey + 所属身份名（列表跨全部身份合并，与 CLI `persona passkey list` 一致） */
interface PasskeyRow {
  passkey: Passkey;
  identityName: string;
}

/** base64/base64url → hex（与 CLI passkey show / 导出 JSON 的展示格式一致） */
const b64ToHex = (b64: string): string => {
  try {
    const binary = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
    let hex = '';
    for (let i = 0; i < binary.length; i++) {
      hex += binary.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return hex;
  } catch {
    return b64; // 解码失败按原样展示
  }
};

const formatDate = (iso?: string): string =>
  iso ? new Date(iso).toLocaleDateString() : '—';

/**
 * Passkey 管理页：跨全部身份列出保险库中的 passkeys（只读元数据），
 * 行点击进详情可自检（本地签名+验签往返）、导出私钥（export_allowed 门禁 +
 * 可能要求重新认证）、删除。创建走浏览器桥接 + 桌面审批链路，不在本页。
 */
const PasskeyPanel: React.FC = () => {
  const { identities } = usePersonaService();
  const [rows, setRows] = useState<PasskeyRow[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<PasskeyRow | null>(null);

  const loadPasskeys = useCallback(async () => {
    if (identities.length === 0) {
      setRows([]);
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const results = await Promise.all(
        identities.map(async (identity) => {
          const res = await personaAPI.passkeyList(identity.id);
          if (!res.success || !res.data) {
            throw new Error(res.error ?? `Failed to list passkeys for ${identity.name}`);
          }
          return res.data.map((passkey) => ({ passkey, identityName: identity.name }));
        }),
      );
      setRows(results.flat());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsLoading(false);
    }
  }, [identities]);

  useEffect(() => {
    void loadPasskeys();
  }, [loadPasskeys]);

  return (
    <div className="space-y-6" data-testid="passkey-panel">
      <section className="bg-white shadow rounded-xl border border-gray-100">
        <div className="p-6 border-b border-gray-100 flex items-center justify-between">
          <div>
            <p className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <FingerPrintIcon className="w-5 h-5 text-gray-400" />
              Passkeys
            </p>
            <p className="text-sm text-gray-500">
              Passkeys stored in your vault, across all identities
            </p>
          </div>
          <button onClick={() => void loadPasskeys()} className="btn-ghost inline-flex items-center" data-testid="passkey-refresh-button">
            {isLoading ? (
              <ArrowPathIcon className="w-4 h-4 mr-1 animate-spin" />
            ) : (
              <ArrowPathIcon className="w-4 h-4 mr-1" />
            )}
            Refresh
          </button>
        </div>

        {error && (
          <div className="m-6 rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-800" data-testid="passkey-error">
            {error}
          </div>
        )}

        {!error && rows.length === 0 && !isLoading && (
          <div className="p-8 text-center text-sm text-gray-500" data-testid="passkey-empty">
            No passkeys yet. Create one from a website's passkey flow.
          </div>
        )}

        {rows.length > 0 && (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Identity</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Relying party</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Account</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">UV</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Export</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last used</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {rows.map((row) => (
                  <tr
                    key={row.passkey.id}
                    onClick={() => setSelected(row)}
                    className="hover:bg-gray-50 cursor-pointer"
                    data-testid={`passkey-row-${row.passkey.id}`}
                  >
                    <td className="px-6 py-3 text-sm text-gray-500">{row.identityName}</td>
                    <td className="px-6 py-3 text-sm text-gray-900 font-medium">
                      {row.passkey.rp_name ?? row.passkey.rp_id}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-700">{row.passkey.user_name ?? '—'}</td>
                    <td className="px-6 py-3 text-sm text-gray-700">{row.passkey.uv_initialized ? '✓' : '✗'}</td>
                    <td className="px-6 py-3 text-sm text-gray-700">{row.passkey.export_allowed ? '✓' : '✗'}</td>
                    <td className="px-6 py-3 text-sm text-gray-500">{formatDate(row.passkey.created_at)}</td>
                    <td className="px-6 py-3 text-sm text-gray-500">{formatDate(row.passkey.last_used_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {selected && (
        <PasskeyDetailModal
          row={selected}
          onClose={() => setSelected(null)}
          onDeleted={() => {
            setSelected(null);
            void loadPasskeys();
          }}
        />
      )}
    </div>
  );
};

interface PasskeyDetailModalProps {
  row: PasskeyRow;
  onClose: () => void;
  /** 删除成功后回调（父级刷新列表并关闭弹窗） */
  onDeleted: () => void;
}

/** 详情弹窗：全字段展示 + 自检 / 导出 / 删除（敏感动作走 REAUTH_REQUIRED → ReauthModal → 重试一次） */
const PasskeyDetailModal: React.FC<PasskeyDetailModalProps> = ({ row, onClose, onDeleted }) => {
  const { passkey } = row;
  const [testStatus, setTestStatus] = useState<'idle' | 'running' | 'passed' | 'failed'>('idle');
  const [testError, setTestError] = useState<string | null>(null);
  const [exportHex, setExportHex] = useState<string | null>(null);
  const [exportCountdown, setExportCountdown] = useState<number | null>(null);
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const reauth = useReauth();
  const selfTestRetryRef = useRef(false);
  const exportRetryRef = useRef(false);

  // 导出值自动隐藏倒计时（照 RevealSecretButton 的 autoHide 模式）
  useEffect(() => {
    if (exportCountdown === null) return;
    if (exportCountdown <= 0) {
      setExportHex(null);
      setExportCountdown(null);
      exportRetryRef.current = false;
      return;
    }
    const timer = window.setTimeout(
      () => setExportCountdown((c) => (c === null ? null : c - 1)),
      1000,
    );
    return () => window.clearTimeout(timer);
  }, [exportCountdown]);

  const runSelfTest = useCallback(async () => {
    setTestStatus('running');
    setTestError(null);
    try {
      const res = await personaAPI.passkeySelfTest(passkey.id);
      if (res.success && res.data) {
        setTestStatus('passed');
        toast.success('Self-test passed');
      } else if (res.error_code === 'REAUTH_REQUIRED') {
        if (!selfTestRetryRef.current && (await reauth.requestReauth())) {
          selfTestRetryRef.current = true;
          await runSelfTest();
        } else {
          setTestStatus('failed');
          setTestError('Re-authentication required');
        }
      } else if (res.error_code === 'SERVICE_LOCKED') {
        setTestStatus('failed');
        setTestError('Service is locked. Unlock and try again.');
      } else {
        setTestStatus('failed');
        setTestError(res.error ?? 'Self-test failed');
      }
    } catch (e) {
      setTestStatus('failed');
      setTestError(e instanceof Error ? e.message : String(e));
    }
  }, [passkey.id, reauth]);

  const runExport = useCallback(async () => {
    setIsExporting(true);
    setExportError(null);
    try {
      const res = await personaAPI.passkeyExportPrivateKey(passkey.id);
      if (res.success && res.data) {
        setExportHex(b64ToHex(res.data));
        setExportCountdown(30);
      } else if (res.error_code === 'REAUTH_REQUIRED') {
        if (!exportRetryRef.current && (await reauth.requestReauth())) {
          exportRetryRef.current = true;
          await runExport();
        } else {
          setExportError('Re-authentication required');
        }
      } else if (res.error_code === 'SERVICE_LOCKED') {
        setExportError('Service is locked. Unlock and try again.');
      } else {
        // 含 export_allowed=false 的 "Passkey export is disabled..."（无专用 error_code）
        setExportError(res.error ?? 'Failed to export private key');
      }
    } catch (e) {
      setExportError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsExporting(false);
    }
  }, [passkey.id, reauth]);

  const handleDelete = async () => {
    if (isDeleting) return;
    const confirmed = window.confirm(
      `Delete the passkey for ${passkey.rp_id}? This cannot be undone.`,
    );
    if (!confirmed) return;
    setIsDeleting(true);
    try {
      const res = await personaAPI.passkeyDelete(passkey.id);
      if (res.success && res.data) {
        toast.success('Passkey deleted');
        onDeleted();
      } else {
        toast.error(res.error ?? 'Failed to delete passkey');
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      role="dialog"
      aria-label="Passkey details"
      data-testid="passkey-detail-modal"
    >
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <h2 className="text-base font-semibold text-gray-900">
            {passkey.rp_name ?? passkey.rp_id}
          </h2>
          <FingerPrintIcon className="w-5 h-5 text-gray-500" />
        </div>

        <div className="px-5 py-4 space-y-3">
          <dl className="text-sm space-y-2">
            <div className="flex gap-2">
              <dt className="text-gray-500 w-28 shrink-0">Relying party</dt>
              <dd className="font-mono text-gray-900 break-all" data-testid="passkey-detail-rp">
                {passkey.rp_id}
              </dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-gray-500 w-28 shrink-0">Identity</dt>
              <dd className="text-gray-900">{row.identityName}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-gray-500 w-28 shrink-0">Account</dt>
              <dd className="text-gray-900 break-all" data-testid="passkey-detail-user">
                {passkey.user_name ?? '—'}
              </dd>
            </div>
            {passkey.user_display_name && (
              <div className="flex gap-2">
                <dt className="text-gray-500 w-28 shrink-0">Display name</dt>
                <dd className="text-gray-900 break-all">{passkey.user_display_name}</dd>
              </div>
            )}
            <div className="flex gap-2">
              <dt className="text-gray-500 w-28 shrink-0">Credential ID</dt>
              <dd className="font-mono text-xs text-gray-700 break-all" data-testid="passkey-detail-credential-id">
                {b64ToHex(passkey.credential_id_b64)}
              </dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-gray-500 w-28 shrink-0">User handle</dt>
              <dd className="font-mono text-xs text-gray-700 break-all">
                {b64ToHex(passkey.user_handle_b64)}
              </dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-gray-500 w-28 shrink-0">Algorithm</dt>
              <dd className="text-gray-900">ES256</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-gray-500 w-28 shrink-0">Verified</dt>
              <dd className="text-gray-900">{passkey.uv_initialized ? 'Yes' : 'No'}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-gray-500 w-28 shrink-0">Export allowed</dt>
              <dd className="text-gray-900">{passkey.export_allowed ? 'Yes' : 'No'}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-gray-500 w-28 shrink-0">Created</dt>
              <dd className="text-gray-900">{new Date(passkey.created_at).toLocaleString()}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-gray-500 w-28 shrink-0">Last used</dt>
              <dd className="text-gray-900">
                {passkey.last_used_at ? new Date(passkey.last_used_at).toLocaleString() : '—'}
              </dd>
            </div>
          </dl>

          {/* 自检：本地签名 + 验签往返（与 RP 相同的检查） */}
          <div className="border-t border-gray-200 pt-3 space-y-2">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => void runSelfTest()}
                disabled={testStatus === 'running'}
                className="btn-ghost inline-flex items-center"
                data-testid="passkey-selftest-button"
              >
                {testStatus === 'running' && <ArrowPathIcon className="w-4 h-4 mr-1 animate-spin" />}
                Run self-test
              </button>
              {testStatus === 'passed' && (
                <span className="text-sm text-green-700" data-testid="passkey-selftest-result">
                  Self-test passed
                </span>
              )}
              {testStatus === 'failed' && testError && (
                <span className="text-sm text-red-600" data-testid="passkey-selftest-result">
                  {testError}
                </span>
              )}
            </div>
          </div>

          {/* 导出私钥（hex）；export_allowed=false 时禁用 */}
          <div className="border-t border-gray-200 pt-3 space-y-2">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => void runExport()}
                disabled={!passkey.export_allowed || isExporting}
                className="btn-ghost inline-flex items-center"
                data-testid="passkey-export-button"
              >
                {isExporting && <ArrowPathIcon className="w-4 h-4 mr-1 animate-spin" />}
                Export private key
              </button>
              {exportCountdown !== null && exportCountdown > 0 && (
                <span className="text-xs text-gray-400 shrink-0" data-testid="passkey-export-countdown">
                  hides in {exportCountdown}s
                </span>
              )}
              {exportHex !== null && (
                <button
                  type="button"
                  onClick={() => void copyWithAutoClear(exportHex)}
                  className="p-1 hover:bg-gray-100 rounded"
                  aria-label="Copy private key"
                >
                  <DocumentDuplicateIcon className="w-4 h-4 text-gray-400" />
                </button>
              )}
            </div>
            {!passkey.export_allowed && (
              <p className="text-xs text-gray-400">Export is disabled for this passkey.</p>
            )}
            {exportHex !== null && (
              <div className="flex items-start gap-2 text-sm text-amber-700 bg-amber-50 border border-amber-200 rounded px-3 py-2">
                <ShieldExclamationIcon className="w-4 h-4 shrink-0 mt-0.5" />
                <span className="font-mono text-xs break-all" data-testid="passkey-export-value">
                  {exportHex}
                </span>
              </div>
            )}
            {exportError && (
              <p className="text-xs text-red-600" data-testid="passkey-export-error">
                {exportError}
              </p>
            )}
          </div>
        </div>

        <div className="px-5 py-4 border-t border-gray-200 flex justify-between">
          <button
            type="button"
            onClick={() => void handleDelete()}
            disabled={isDeleting}
            className="btn-ghost inline-flex items-center text-red-600 hover:text-red-700"
            data-testid="passkey-delete-button"
          >
            <TrashIcon className="w-4 h-4 mr-1" />
            Delete
          </button>
          <button type="button" onClick={onClose} className="btn-primary">
            Close
          </button>
        </div>

        <ReauthModal
          isOpen={reauth.isOpen}
          error={reauth.error}
          isVerifying={reauth.isVerifying}
          onSubmit={reauth.submit}
          onClose={reauth.cancel}
        />
      </div>
    </div>
  );
};

export default PasskeyPanel;
