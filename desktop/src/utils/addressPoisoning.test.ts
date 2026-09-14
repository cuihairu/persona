import { looksLikeAddressPoisoning } from './addressPoisoning';

describe('looksLikeAddressPoisoning', () => {
  const known = ['0x1234567890abcdef1234567890abcdef12345678'];

  it('flags same head+tail with different middle', () => {
    const attacker = '0x123456FFFFFFFF1234567890abcdef12345678';
    expect(looksLikeAddressPoisoning(attacker, known)).toBe(known[0]);
  });

  it('ignores the exact same address (case-insensitive)', () => {
    expect(looksLikeAddressPoisoning(known[0].toUpperCase(), known)).toBeNull();
  });

  it('ignores same head but different tail', () => {
    const mimic = '0x1234567890abcdef1234567890abcdef99999999';
    expect(looksLikeAddressPoisoning(mimic, known)).toBeNull();
  });

  it('ignores same tail but different head', () => {
    const mimic = '0x9999997890abcdef1234567890abcdef12345678';
    expect(looksLikeAddressPoisoning(mimic, known)).toBeNull();
  });

  it('returns null for too-short addresses', () => {
    expect(looksLikeAddressPoisoning('0x1234', known)).toBeNull();
  });

  it('returns null when known list is empty', () => {
    expect(looksLikeAddressPoisoning('0x1234567890abcdef1234567890abcdef12345678', [])).toBeNull();
  });

  it('detects mimicry among multiple known addresses', () => {
    const knownMany = [
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      'solanaBase58AddressHead111111TailABCDEF',
    ];
    // 同前缀 + 同尾缀，仅中段不同 → 疑似模仿
    const mimic = 'solanaBase58AddressHead222222TailABCDEF';
    expect(looksLikeAddressPoisoning(mimic, knownMany)).toBe(knownMany[1]);
  });
});
