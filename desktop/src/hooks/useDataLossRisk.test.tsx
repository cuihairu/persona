import { computeDataLossRisk } from '@/hooks/useDataLossRisk';

describe('computeDataLossRisk', () => {
  it('returns none when not joined', () => {
    expect(computeDataLossRisk({ joined: false, deviceCount: 1, hasBackup: false, hasAccount: false })).toBe('none');
  });

  it('returns none when deviceCount >= 2', () => {
    expect(computeDataLossRisk({ joined: true, deviceCount: 2, hasBackup: false, hasAccount: false })).toBe('none');
  });

  it('returns none when hasBackup is true', () => {
    expect(computeDataLossRisk({ joined: true, deviceCount: 1, hasBackup: true, hasAccount: false })).toBe('none');
  });

  it('returns medium when hasAccount is true and no backup', () => {
    expect(computeDataLossRisk({ joined: true, deviceCount: 1, hasBackup: false, hasAccount: true })).toBe('medium');
  });

  it('returns high when no account, no backup, single device, joined', () => {
    expect(computeDataLossRisk({ joined: true, deviceCount: 1, hasBackup: false, hasAccount: false })).toBe('high');
  });
});