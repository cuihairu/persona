import { act, renderHook, waitFor } from '@testing-library/react';
import { useReauth } from './useReauth';
import { personaAPI } from '@/utils/api';

describe('hooks/useReauth', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
  });

  it('opens the dialog and resolves true after a successful verify', async () => {
    const verify = jest
      .spyOn(personaAPI, 'reauthVerify')
      .mockResolvedValue({ success: true, data: true, error: undefined });

    const { result } = renderHook(() => useReauth());

    let promise: Promise<boolean> | undefined;
    act(() => {
      promise = result.current.requestReauth();
    });
    expect(result.current.isOpen).toBe(true);

    await act(async () => {
      await result.current.submit('master-pw');
    });

    await waitFor(async () => {
      expect(promise).resolves.toBe(true);
    });
    expect(verify).toHaveBeenCalledWith('master-pw');
    expect(result.current.isOpen).toBe(false);
    expect(result.current.error).toBeNull();
    expect(result.current.isVerifying).toBe(false);
  });

  it('keeps the dialog open with the API error when verification fails', async () => {
    jest.spyOn(personaAPI, 'reauthVerify').mockResolvedValue({
      success: false,
      data: undefined,
      error: 'Invalid master password',
    });

    const { result } = renderHook(() => useReauth());
    let promise: Promise<boolean> | undefined;
    act(() => {
      promise = result.current.requestReauth();
    });

    await act(async () => {
      await result.current.submit('wrong');
    });

    expect(result.current.isOpen).toBe(true);
    expect(result.current.error).toBe('Invalid master password');
    expect(result.current.isVerifying).toBe(false);

    // 挂起的 promise 仍未决 → cancel 走失败路径
    act(() => {
      result.current.cancel();
    });
    expect(result.current.isOpen).toBe(false);
    expect(promise).resolves.toBe(false);
  });

  it('surfaces thrown verification errors and does not resolve the promise', async () => {
    jest.spyOn(personaAPI, 'reauthVerify').mockRejectedValue(new Error('bridge down'));

    const { result } = renderHook(() => useReauth());
    let settled = false;
    let promise: Promise<boolean> | undefined;
    act(() => {
      promise = result.current.requestReauth().then((ok) => {
        settled = true;
        return ok;
      });
    });

    await act(async () => {
      await result.current.submit('pw');
    });

    expect(result.current.error).toBe('bridge down');
    expect(settled).toBe(false);
    act(() => {
      result.current.cancel();
    });
    expect(promise).resolves.toBe(false);
  });

  it('reports a non-Error rejection as a string and resets verifying state', async () => {
    jest.spyOn(personaAPI, 'reauthVerify').mockRejectedValue('boom');

    const { result } = renderHook(() => useReauth());
    act(() => {
      result.current.requestReauth();
    });

    await act(async () => {
      await result.current.submit('pw');
    });
    expect(result.current.error).toBe('boom');
    expect(result.current.isVerifying).toBe(false);
  });

  it('cancel resolves false without touching the API', async () => {
    const verify = jest.spyOn(personaAPI, 'reauthVerify');
    const { result } = renderHook(() => useReauth());

    let promise: Promise<boolean> | undefined;
    act(() => {
      promise = result.current.requestReauth();
    });
    act(() => {
      result.current.cancel();
    });

    expect(promise).resolves.toBe(false);
    expect(verify).not.toHaveBeenCalled();
  });
});
