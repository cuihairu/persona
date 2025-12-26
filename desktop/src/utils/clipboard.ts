import { readText as tauriReadText, writeText as tauriWriteText } from '@tauri-apps/api/clipboard';

const writeClipboardText = async (text: string): Promise<boolean> => {
  try {
    await tauriWriteText(text);
    return true;
  } catch (_err) {
    // ignore and fall back
  }

  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (_err) {
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
  } catch (_err) {
    // ignore and fall back
  }

  try {
    if (navigator.clipboard?.readText) {
      return await navigator.clipboard.readText();
    }
  } catch (_err) {
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
