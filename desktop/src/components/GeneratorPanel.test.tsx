import { fireEvent, render, waitFor } from '@testing-library/react';
import GeneratorPanel from './GeneratorPanel';
import { personaAPI } from '@/utils/api';
import type { GeneratedPasswords } from '@/types';

jest.mock('@/utils/api', () => ({
  personaAPI: { generatePasswordAdvanced: jest.fn() },
}));

jest.mock('@/utils/clipboard', () => ({
  copyToClipboardWithToast: jest.fn(),
}));

const mockGenerate = personaAPI.generatePasswordAdvanced as jest.Mock;
const mockCopy = jest.requireMock('@/utils/clipboard').copyToClipboardWithToast as jest.Mock;

const mkResult = (overrides?: Partial<GeneratedPasswords>): GeneratedPasswords => ({
  passwords: ['aB1!aB1!aB1!aB1!'],
  entropy_bits: 102.7,
  pool_size: 86,
  ...overrides,
});

beforeEach(() => {
  mockGenerate.mockReset();
  mockCopy.mockReset();
});

describe('components/GeneratorPanel', () => {
  it('renders controls with defaults and no results before generating', () => {
    const { getByTestId, queryByTestId } = render(<GeneratorPanel />);

    expect(getByTestId('generator-length-value')).toHaveTextContent('16');
    expect(getByTestId('generator-count-select')).toHaveValue('3');
    expect(getByTestId('generator-toggle-lowercase')).toHaveTextContent('小写字母');
    expect(getByTestId('generator-toggle-pronounceable')).toHaveTextContent('可发音');
    expect(queryByTestId('generator-results')).not.toBeInTheDocument();
    expect(mockGenerate).not.toHaveBeenCalled();
  });

  it('generates passwords and renders the entropy meter plus copyable candidates', async () => {
    mockGenerate.mockResolvedValue({
      success: true,
      data: mkResult({
        passwords: ['aB1!aB1!aB1!aB1!', 'Zz9?Zz9?Zz9?Zz9?'],
        entropy_bits: 102.7,
        pool_size: 86,
      }),
    });

    const { getByTestId, getAllByRole } = render(<GeneratorPanel />);
    fireEvent.click(getByTestId('generator-generate'));

    await waitFor(() => {
      expect(getByTestId('generator-results')).toBeInTheDocument();
    });
    expect(mockGenerate).toHaveBeenCalledWith({
      length: 16,
      include_lowercase: true,
      include_uppercase: true,
      include_numbers: true,
      include_symbols: true,
      pronounceable: false,
      count: 3,
    });
    expect(getByTestId('generator-password-0')).toHaveTextContent('aB1!aB1!aB1!aB1!');
    expect(getByTestId('generator-password-1')).toHaveTextContent('Zz9?Zz9?Zz9?Zz9?');
    expect(getByTestId('generator-entropy-value')).toHaveTextContent('103');
    // 102.7/128 ≈ 80.2% wide strong-password color bar
    expect(getByTestId('generator-entropy-bar')).toHaveAttribute(
      'style',
      expect.stringContaining('80.2')
    );

    fireEvent.click(getByTestId('generator-copy-1'));
    expect(mockCopy).toHaveBeenCalledWith('Zz9?Zz9?Zz9?Zz9?', '密码');

    // Keyboard accessibility: copy is a plain button
    expect(getAllByRole('button', { name: '复制' }).length).toBeGreaterThanOrEqual(2);
  });

  it('passes option changes through to the command', async () => {
    mockGenerate.mockResolvedValue({ success: true, data: mkResult() });

    const { getByTestId } = render(<GeneratorPanel />);
    fireEvent.change(getByTestId('generator-length-input'), { target: { value: '32' } });
    fireEvent.change(getByTestId('generator-count-select'), { target: { value: '5' } });
    fireEvent.click(getByTestId('generator-toggle-symbols')); // turn symbols off
    fireEvent.click(getByTestId('generator-toggle-pronounceable')); // turn pronounceable on

    fireEvent.click(getByTestId('generator-generate'));
    await waitFor(() => expect(mockGenerate).toHaveBeenCalled());
    expect(mockGenerate).toHaveBeenLastCalledWith({
      length: 32,
      include_lowercase: true,
      include_uppercase: true,
      include_numbers: true,
      include_symbols: false,
      pronounceable: true,
      count: 5,
    });
  });

  it('disables generate when pronounceable has no letter set and shows the hint', () => {
    const { getByTestId, getByText } = render(<GeneratorPanel />);

    fireEvent.click(getByTestId('generator-toggle-lowercase'));
    fireEvent.click(getByTestId('generator-toggle-uppercase'));
    fireEvent.click(getByTestId('generator-toggle-pronounceable'));

    expect(getByTestId('generator-generate')).toBeDisabled();
    expect(getByText('可发音模式需要至少勾选一个字母集')).toBeInTheDocument();
  });

  it('disables generate when no character set is selected at all', () => {
    const { getByTestId, getByText } = render(<GeneratorPanel />);

    fireEvent.click(getByTestId('generator-toggle-lowercase'));
    fireEvent.click(getByTestId('generator-toggle-uppercase'));
    fireEvent.click(getByTestId('generator-toggle-numbers'));
    fireEvent.click(getByTestId('generator-toggle-symbols'));

    expect(getByTestId('generator-generate')).toBeDisabled();
    expect(getByText('至少需要勾选一个字符集')).toBeInTheDocument();
  });

  it('surfaces backend validation errors instead of silently failing', async () => {
    mockGenerate.mockResolvedValue({
      success: false,
      error: 'At least one character set must be enabled',
    });

    const { getByTestId } = render(<GeneratorPanel />);
    fireEvent.click(getByTestId('generator-generate'));

    await waitFor(() => {
      expect(getByTestId('generator-error')).toHaveTextContent('At least one character set');
    });
    // After an error, the previous result is no longer rendered
    expect(document.querySelector('[data-testid="generator-results"]')).toBeNull();
  });

  it('shows very-weak styling for low entropy', async () => {
    mockGenerate.mockResolvedValue({
      success: true,
      data: mkResult({ passwords: ['aaaa'], entropy_bits: 20, pool_size: 26 }),
    });

    const { getByTestId, getByText } = render(<GeneratorPanel />);
    fireEvent.click(getByTestId('generator-generate'));

    await waitFor(() => expect(getByTestId('generator-results')).toBeInTheDocument());
    expect(getByTestId('generator-entropy-bar').className).toContain('bg-red-500');
    // The strength row renders the strength label and value as two separate text nodes, so match by substring
    expect(getByText(/非常弱/)).toBeInTheDocument();
  });

  it('swaps the length slider for a word-count slider in words mode', () => {
    const { getByTestId, queryByTestId, getByText, queryByText } = render(<GeneratorPanel />);

    expect(getByTestId('generator-length-input')).toBeInTheDocument();
    expect(queryByTestId('generator-words-input')).not.toBeInTheDocument();

    fireEvent.click(getByTestId('generator-toggle-words'));

    expect(queryByTestId('generator-length-input')).not.toBeInTheDocument();
    expect(getByTestId('generator-words-value')).toHaveTextContent('5');
    expect(getByText(/EFF 大词表/)).toBeInTheDocument();

    // Words mode generates even with no character set ticked (core short-circuits into Diceware), and no warning bar appears
    fireEvent.click(getByTestId('generator-toggle-lowercase'));
    fireEvent.click(getByTestId('generator-toggle-uppercase'));
    fireEvent.click(getByTestId('generator-toggle-numbers'));
    fireEvent.click(getByTestId('generator-toggle-symbols'));
    expect(getByTestId('generator-generate')).toBeEnabled();
    expect(queryByText('至少需要勾选一个字符集')).not.toBeInTheDocument();

    // Turning words off restores the length slider
    fireEvent.click(getByTestId('generator-toggle-words'));
    expect(getByTestId('generator-length-input')).toBeInTheDocument();
    expect(queryByTestId('generator-words-input')).not.toBeInTheDocument();
  });

  it('passes the word count through and ignores charset constraints in words mode', async () => {
    mockGenerate.mockResolvedValue({
      success: true,
      data: mkResult({
        passwords: ['wrong-donkey-battery-staple'],
        entropy_bits: 51.7,
        pool_size: 7772,
      }),
    });

    const { getByTestId } = render(<GeneratorPanel />);
    fireEvent.click(getByTestId('generator-toggle-words'));
    // All character sets off: words mode still generates
    fireEvent.click(getByTestId('generator-toggle-lowercase'));
    fireEvent.click(getByTestId('generator-toggle-uppercase'));
    fireEvent.click(getByTestId('generator-toggle-numbers'));
    fireEvent.click(getByTestId('generator-toggle-symbols'));
    fireEvent.change(getByTestId('generator-words-input'), { target: { value: '7' } });

    fireEvent.click(getByTestId('generator-generate'));
    await waitFor(() => expect(getByTestId('generator-results')).toBeInTheDocument());
    expect(mockGenerate).toHaveBeenCalledWith({
      length: 16,
      include_lowercase: false,
      include_uppercase: false,
      include_numbers: false,
      include_symbols: false,
      pronounceable: false,
      count: 3,
      words: 7,
    });
  });
});
