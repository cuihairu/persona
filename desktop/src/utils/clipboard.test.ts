import { copyWithAutoClear } from './clipboard';

const mockTauriWriteText = jest.fn();
const mockTauriReadText = jest.fn();

jest.mock('@tauri-apps/api/clipboard', () => ({
  writeText: (...args: any[]) => mockTauriWriteText(...args),
  readText: (...args: any[]) => mockTauriReadText(...args),
}));

describe('utils/clipboard', () => {
  beforeEach(() => {
    mockTauriWriteText.mockReset();
    mockTauriReadText.mockReset();
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
});

