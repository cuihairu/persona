import { readText as tauriReadText, writeText as tauriWriteText } from '@tauri-apps/plugin-clipboard-manager';
import toast from 'react-hot-toast';

const writeClipboardText = async (text: string): Promise<boolean> => {
  try {
    await tauriWriteText(text);
    return true;
  } catch {
    // ignore and fall back
  }

  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // ignore and fall back
  }

  try {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textArea);
    return ok;
  } catch {
    return false;
  }
};

const readClipboardText = async (): Promise<string | null> => {
  try {
    return await tauriReadText();
  } catch {
    // ignore and fall back
  }

  try {
    if (navigator.clipboard?.readText) {
      return await navigator.clipboard.readText();
    }
  } catch {
    // ignore and fall back
  }

  return null;
};

export const copyWithAutoClear = async (
  text: string,
  clearAfterMs: number = 30_000,
): Promise<boolean> => {
  const ok = await writeClipboardText(text);
  if (!ok) return false;

  window.setTimeout(async () => {
    const current = await readClipboardText();
    if (current === text) {
      await writeClipboardText('');
    }
  }, clearAfterMs);

  return true;
};

/** 复制 + 结果 toast（30s 自动清除）。CredentialList 行内按钮与全局 ⌘E 共用 */
export const copyToClipboardWithToast = async (text: string, label: string): Promise<void> => {
  const ok = await copyWithAutoClear(text, 30_000);
  if (ok) {
    toast.success(`${label} copied (clears in 30s)`);
  } else {
    toast.error('Failed to copy to clipboard');
  }
};
