import {
  cn,
  copyToClipboard,
  formatDate,
  generateSecurePassword,
  getRelativeTime,
  validateEmail,
  validateUrl,
} from './helpers';

describe('utils/helpers', () => {
  it('cn joins truthy classes', () => {
    expect(cn('a', undefined, false, 'b', null, 'c')).toBe('a b c');
  });

  it('validateEmail validates common emails', () => {
    expect(validateEmail('test@example.com')).toBe(true);
    expect(validateEmail('nope')).toBe(false);
  });

  it('validateUrl validates http(s) URLs', () => {
    expect(validateUrl('https://example.com')).toBe(true);
    expect(validateUrl('not a url')).toBe(false);
  });

  it('formatDate delegates to toLocaleDateString', () => {
    const spy = jest
      .spyOn(Date.prototype, 'toLocaleDateString')
      .mockReturnValue('Jan 01, 2023, 00:00 AM');
    expect(formatDate(new Date('2023-01-01T00:00:00Z'))).toBe('Jan 01, 2023, 00:00 AM');
    spy.mockRestore();
  });

  it('getRelativeTime returns expected buckets', () => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2024-01-10T12:00:00Z'));

    expect(getRelativeTime('2024-01-10T00:00:00Z')).toBe('Today');
    expect(getRelativeTime('2024-01-09T00:00:00Z')).toBe('Yesterday');
    expect(getRelativeTime('2024-01-06T00:00:00Z')).toBe('4 days ago');
    expect(getRelativeTime('2023-12-30T00:00:00Z')).toBe('1 weeks ago');
    expect(getRelativeTime('2023-09-10T00:00:00Z')).toBe('4 months ago');

    jest.useRealTimers();
  });

  it('generateSecurePassword generates correct length and charset', () => {
    const originalCrypto = window.crypto;
    (window as any).crypto = {
      getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = i;
        return arr;
      },
    };

    const password = generateSecurePassword(16, false);
    expect(password).toHaveLength(16);
    expect(password).toMatch(/^[a-zA-Z0-9]+$/);

    (window as any).crypto = originalCrypto;
  });

  it('copyToClipboard uses navigator.clipboard when available', async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    (navigator as any).clipboard = { writeText };

    await expect(copyToClipboard('hello')).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith('hello');
  });

  it('copyToClipboard falls back to execCommand when clipboard API fails', async () => {
    const writeText = jest.fn().mockRejectedValue(new Error('nope'));
    (navigator as any).clipboard = { writeText };
    (document as any).execCommand = jest.fn().mockReturnValue(true);

    await expect(copyToClipboard('hello')).resolves.toBe(true);
    expect((document as any).execCommand).toHaveBeenCalledWith('copy');
  });
});

