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

  // -- 补全：tauri 之后的浏览器 fallback 链 --------------------------------

  /** 临时替换 jsdom navigator.clipboard（可能本来就没有该属性）。 */
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

    // execCommand 报 false → 写入失败
    execCommand.mockReturnValue(false);
    await expect(copyWithAutoClear('s', 30_000)).resolves.toBe(false);

    // execCommand 抛异常 → catch → false
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
    // 清空回调链路较长（tauri 读 reject → navigator 读 → 比较 → 再写），
    // 用足够多的微任务 tick 把整条 await 链冲完
    for (let i = 0; i < 20; i++) {
      await Promise.resolve();
    }

    // tauri 读失败 → navigator 读到相同内容 → 清空（写链仍是 tauri 主路）
    expect(mockTauriReadText).toHaveBeenCalled();
    expect(readText).toHaveBeenCalled();
    expect(mockTauriWriteText).toHaveBeenLastCalledWith('');

    // navigator 也没有 readText → 读不到 → 不清空
    const restore2 = setNavigatorClipboard({ writeText } as any);
    mockTauriWriteText.mockClear();
    await expect(copyWithAutoClear('x', 10)).resolves.toBe(true);
    jest.advanceTimersByTime(10);
    await Promise.resolve();
    await Promise.resolve();
    expect(mockTauriWriteText).toHaveBeenCalledTimes(1); // 只有最初那次写
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

