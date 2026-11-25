import { copyWithAutoClear, copyToClipboardWithToast } from './clipboard';

const mockTauriWriteText = jest.fn();
const mockTauriReadText = jest.fn();
const mockToastSuccess = jest.fn();
const mockToastError = jest.fn();

jest.mock('@tauri-apps/plugin-clipboard-manager', () => ({
  writeText: (...args: any[]) => mockTauriWriteText(...args),
  readText: (...args: any[]) => mockTauriReadText(...args),
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    success: (...args: any[]) => mockToastSuccess(...args),
    error: (...args: any[]) => mockToastError(...args),
  },
}));

describe('utils/clipboard', () => {
  beforeEach(() => {
    mockTauriWriteText.mockReset();
    mockTauriReadText.mockReset();
    mockToastSuccess.mockReset();
    mockToastError.mockReset();
  });

  it('writes via tauri clipboard and auto-clears when content unchanged', async () => {
    jest.useFakeTimers();

    mockTauriWriteText.mockResolvedValue(undefined);
    mockTauriReadText.mockResolvedValue('secret');

    await expect(copyWithAutoClear('secret', 10)).resolves.toBe(true);

    expect(mockTauriWriteText).toHaveBeenCalledWith('secret');

    jest.advanceTimersByTime(10);
    await Promise.resolve();
    await Promise.resolve();

    expect(mockTauriReadText).toHaveBeenCalled();
    expect(mockTauriWriteText).toHaveBeenLastCalledWith('');

    jest.useRealTimers();
  });

  it('does not clear when clipboard content changed', async () => {
    jest.useFakeTimers();

    mockTauriWriteText.mockResolvedValue(undefined);
    mockTauriReadText.mockResolvedValue('different');

    await expect(copyWithAutoClear('secret', 10)).resolves.toBe(true);
    jest.advanceTimersByTime(10);
    await Promise.resolve();
    await Promise.resolve();

    expect(mockTauriWriteText).toHaveBeenCalledTimes(1);

    jest.useRealTimers();
  });

  // -- Completion: the browser fallback chain after tauri --------------------------------

  /** Temporarily replaces the jsdom navigator.clipboard (which may not exist at all). */
  const setNavigatorClipboard = (impl: Partial<Clipboard> | undefined) => {
    const original = (navigator as any).clipboard;
    if (impl === undefined) {
      Object.defineProperty(navigator, 'clipboard', {
        value: undefined,
        configurable: true,
      });
    } else {
      Object.defineProperty(navigator, 'clipboard', {
        value: impl,
        configurable: true,
      });
    }
    return () => {
      Object.defineProperty(navigator, 'clipboard', {
        value: original,
        configurable: true,
      });
    };
  };

  it('falls back to navigator.clipboard.writeText when the tauri backend refuses', async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    const restore = setNavigatorClipboard({ writeText } as any);
    mockTauriWriteText.mockRejectedValue(new Error('no backend'));

    await expect(copyWithAutoClear('s', 30_000)).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith('s');
    restore();
  });

  it('falls back to execCommand when both tauri and navigator writes fail', async () => {
    setNavigatorClipboard(undefined);
    mockTauriWriteText.mockRejectedValue(new Error('no backend'));

    const execCommand = jest.fn().mockReturnValue(true);
    document.execCommand = execCommand as any;

    await expect(copyWithAutoClear('s', 30_000)).resolves.toBe(true);
    expect(execCommand).toHaveBeenCalledWith('copy');

    // execCommand returns false → write failed
    execCommand.mockReturnValue(false);
    await expect(copyWithAutoClear('s', 30_000)).resolves.toBe(false);

    // execCommand throws → caught → false
    execCommand.mockImplementation(() => {
      throw new Error('denied');
    });
    await expect(copyWithAutoClear('s', 30_000)).resolves.toBe(false);
  });

  it('auto-clear falls back to navigator read then gives up with null', async () => {
    jest.useFakeTimers();

    const readText = jest.fn().mockResolvedValue('secret');
    const writeText = jest.fn().mockResolvedValue(undefined);
    const restore = setNavigatorClipboard({ readText, writeText } as any);
    mockTauriWriteText.mockResolvedValue(undefined);
    mockTauriReadText.mockRejectedValue(new Error('no backend'));

    await expect(copyWithAutoClear('secret', 10)).resolves.toBe(true);

    jest.advanceTimersByTime(10);
    // The clear callback chain is long (tauri read rejects → navigator read →
    // comparison → write again), so flush the entire await chain with enough
    // microtask ticks
    for (let i = 0; i < 20; i++) {
      await Promise.resolve();
    }

    // tauri read fails → navigator reads the same content → clear (the write chain still goes through tauri as the primary path)
    expect(mockTauriReadText).toHaveBeenCalled();
    expect(readText).toHaveBeenCalled();
    expect(mockTauriWriteText).toHaveBeenLastCalledWith('');

    // navigator has no readText either → cannot read → do not clear
    const restore2 = setNavigatorClipboard({ writeText } as any);
    mockTauriWriteText.mockClear();
    await expect(copyWithAutoClear('x', 10)).resolves.toBe(true);
    jest.advanceTimersByTime(10);
    await Promise.resolve();
    await Promise.resolve();
    expect(mockTauriWriteText).toHaveBeenCalledTimes(1); // only the initial write
    restore2();
    restore();

    jest.useRealTimers();
  });

  it('copyToClipboardWithToast toasts success with the 30s hint', async () => {
    mockTauriWriteText.mockResolvedValue(undefined);

    await copyToClipboardWithToast('alice', 'Username');

    expect(mockTauriWriteText).toHaveBeenCalledWith('alice');
    expect(mockToastSuccess).toHaveBeenCalledWith('Username 已复制（30 秒后自动清除）');
    expect(mockToastError).not.toHaveBeenCalled();
  });

  it('copyToClipboardWithToast toasts the failure message on failure', async () => {
    mockTauriWriteText.mockRejectedValue(new Error('no backend'));
    setNavigatorClipboard(undefined);
    const execCommand = jest.fn().mockReturnValue(false);
    document.execCommand = execCommand as any;

    await copyToClipboardWithToast('alice', 'Username');

    expect(mockToastSuccess).not.toHaveBeenCalled();
    expect(mockToastError).toHaveBeenCalledWith('复制到剪贴板失败');
  });
});

