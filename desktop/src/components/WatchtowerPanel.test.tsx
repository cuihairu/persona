import { fireEvent, render, waitFor } from '@testing-library/react';
import WatchtowerPanel from './WatchtowerPanel';
import { personaAPI } from '@/utils/api';
import type { HealthReport } from '@/types';

jest.mock('@/utils/api', () => ({
  personaAPI: { healthScan: jest.fn() },
}));

const mockHealthScan = personaAPI.healthScan as jest.Mock;

const mkReport = (overrides?: Partial<HealthReport>): HealthReport => ({
  scanned_at: '2026-09-15T00:00:00Z',
  total_credentials: 2,
  issues: [],
  counts: { high: 0, medium: 0, low: 0 },
  ...overrides,
});

beforeEach(() => {
  mockHealthScan.mockReset();
});

describe('components/WatchtowerPanel', () => {
  it('does not scan on mount and shows the guidance state', () => {
    const { getByText } = render(<WatchtowerPanel />);
    expect(getByText('Run a scan to check your vault.')).toBeInTheDocument();
    expect(mockHealthScan).not.toHaveBeenCalled();
  });

  it('runs a scan and renders issue rows', async () => {
    mockHealthScan.mockResolvedValue({
      success: true,
      data: mkReport({
        total_credentials: 2,
        counts: { high: 1, medium: 0, low: 1 },
        issues: [
          {
            credential_id: '11111111-1111-1111-1111-111111111111',
            credential_name: 'Github',
            credential_type: 'Password',
            severity: 'high',
            detail: 'This password appears 65764 time(s) in known breach corpora. Rotate it now.',
            type: 'breached_password',
            count: 65764,
          },
          {
            credential_id: '22222222-2222-2222-2222-222222222222',
            credential_name: 'Jenkins',
            credential_type: 'ServerConfig',
            severity: 'low',
            detail: 'Unchanged for 400 day(s). Verify it is still needed and current.',
            type: 'stale_unchanged',
            days: 400,
          },
        ],
      }),
    });

    const { getByText, getByRole } = render(<WatchtowerPanel />);
    fireEvent.click(getByRole('button', { name: 'Run Scan' }));

    await waitFor(() => {
      expect(mockHealthScan).toHaveBeenCalledWith({ check_breaches: false });
      expect(getByText('Github')).toBeInTheDocument();
    });
    expect(
      getByText('This password appears 65764 time(s) in known breach corpora. Rotate it now.'),
    ).toBeInTheDocument();
    expect(getByText('breached password')).toBeInTheDocument();
    expect(getByText('Jenkins')).toBeInTheDocument();
    expect(getByText('stale')).toBeInTheDocument();
  });

  it('renders the 2FA-available hint with its site label', async () => {
    mockHealthScan.mockResolvedValue({
      success: true,
      data: mkReport({
        total_credentials: 1,
        counts: { high: 0, medium: 0, low: 1 },
        issues: [
          {
            credential_id: '33333333-3333-3333-3333-333333333333',
            credential_name: 'GitHub',
            credential_type: 'Password',
            severity: 'low',
            detail:
              'github.com offers two-factor authentication, but no TOTP is stored for it in this vault. Add a TOTP credential to strengthen the login.',
            type: 'two_factor_available',
            site: 'github.com',
          },
        ],
      }),
    });

    const { getByText, getByRole } = render(<WatchtowerPanel />);
    fireEvent.click(getByRole('button', { name: 'Run Scan' }));

    await waitFor(() => {
      expect(getByText('GitHub')).toBeInTheDocument();
    });
    expect(getByText('2FA available')).toBeInTheDocument();
    expect(getByText(/github\.com offers two-factor authentication/)).toBeInTheDocument();
  });

  it('passes check_breaches: true when the checkbox is ticked', async () => {
    mockHealthScan.mockResolvedValue({ success: true, data: mkReport() });

    const { getByLabelText, getByRole } = render(<WatchtowerPanel />);
    fireEvent.click(getByLabelText(/Check breach corpora \(HIBP\)/));
    fireEvent.click(getByRole('button', { name: 'Run Scan' }));

    await waitFor(() => {
      expect(mockHealthScan).toHaveBeenCalledWith({ check_breaches: true });
    });
  });

  it('shows the error message when the scan fails', async () => {
    mockHealthScan.mockResolvedValue({
      success: false,
      error: 'Health scan failed: boom',
    });

    const { getByText, getByRole } = render(<WatchtowerPanel />);
    fireEvent.click(getByRole('button', { name: 'Run Scan' }));

    await waitFor(() => {
      expect(getByText('Health scan failed: boom')).toBeInTheDocument();
    });
  });

  it('shows the clean-vault empty state for an issue-free report', async () => {
    mockHealthScan.mockResolvedValue({
      success: true,
      data: mkReport({ total_credentials: 7 }),
    });

    const { getByText, getByRole } = render(<WatchtowerPanel />);
    fireEvent.click(getByRole('button', { name: 'Run Scan' }));

    await waitFor(() => {
      expect(getByText('✓ No issues found across 7 credential(s).')).toBeInTheDocument();
    });
  });

  it('summarizes severity counts from the report', async () => {
    mockHealthScan.mockResolvedValue({
      success: true,
      data: mkReport({
        counts: { high: 2, medium: 1, low: 3 },
        issues: [
          {
            credential_id: '33333333-3333-3333-3333-333333333333',
            credential_name: 'Old VPN',
            credential_type: 'Password',
            severity: 'low',
            detail: 'Unchanged for 500 day(s). Verify it is still needed and current.',
            type: 'stale_unchanged',
            days: 500,
          },
        ],
      }),
    });

    const { getByText, getByRole } = render(<WatchtowerPanel />);
    fireEvent.click(getByRole('button', { name: 'Run Scan' }));

    await waitFor(() => {
      expect(getByText('2 high')).toBeInTheDocument();
    });
    expect(getByText('1 medium')).toBeInTheDocument();
    expect(getByText('3 low')).toBeInTheDocument();
  });
});
