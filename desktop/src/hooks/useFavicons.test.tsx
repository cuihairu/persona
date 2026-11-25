import { act, render } from '@testing-library/react';
import { useFavicons, __resetFaviconInFlight } from './useFavicons';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';
import { personaAPI } from '@/utils/api';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    getFavicons: jest.fn(),
  },
}));

const mockGetFavicons = personaAPI.getFavicons as jest.Mock;

/** Minimal probe: renders the value returned by faviconFor */
const Probe = ({ urls }: { urls: (string | null)[] }) => {
  const { faviconFor } = useFavicons(urls);
  return (
    <div>
      {urls.map((u, i) => (
        <span key={i} data-testid={`probe-${i}`}>
          {JSON.stringify(faviconFor(u))}
        </span>
      ))}
    </div>
  );
};

const FLAG_ON = { ...DEFAULT_FEATURE_FLAGS, fetch_favicons: true };

describe('hooks/useFavicons', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    __resetFaviconInFlight();
    useAppStore.setState({
      featureFlags: { ...DEFAULT_FEATURE_FLAGS },
      faviconCache: {},
      faviconMisses: {},
    });
  });

  const readProbe = (container: HTMLElement, i: number) =>
    container.querySelector(`[data-testid="probe-${i}"]`)!.textContent;

  it('never requests and returns null when the flag is off', async () => {
    const { container } = render(<Probe urls={['https://a.com/x']} />);

    await act(async () => {});
    // flag off: no request, faviconFor always null
    expect(mockGetFavicons).not.toHaveBeenCalled();
    expect(readProbe(container, 0)).toBe('null');
  });

  it('dedupes hosts, batches one IPC, caches hits and flags misses', async () => {
    useAppStore.setState({ featureFlags: { ...FLAG_ON } });
    mockGetFavicons.mockResolvedValueOnce({
      success: true,
      data: [{ host: 'a.com', mime_type: 'image/png', data: 'AAA' }],
    });

    const urls = ['https://a.com/one', 'https://A.com/two', 'https://b.com', null];
    const { container, rerender } = render(<Probe urls={urls} />);

    await act(async () => {});
    expect(mockGetFavicons).toHaveBeenCalledTimes(1);
    // Normalized dedupe: a.com merges across cases; nulls are dropped; ordering is stable
    expect(mockGetFavicons).toHaveBeenCalledWith(['a.com', 'b.com']);

    // Hits enter the cache; misses land in the negative cache
    expect(useAppStore.getState().faviconCache['a.com']).toEqual({
      mime_type: 'image/png',
      data: 'AAA',
    });
    expect(useAppStore.getState().faviconMisses).toEqual({ 'b.com': true });
    expect(readProbe(container, 0)).toContain('"data":"AAA"');
    expect(readProbe(container, 2)).toBe('null');

    // Render again (same hosts): neither hits nor negative-cache entries trigger a request
    mockGetFavicons.mockClear();
    rerender(<Probe urls={urls} />);
    await act(async () => {});
    expect(mockGetFavicons).not.toHaveBeenCalled();

    // faviconFor is always null for a missing url
    expect(readProbe(container, 3)).toBe('null');
  });

  it('does not flag misses when the batch read fails', async () => {
    useAppStore.setState({ featureFlags: { ...FLAG_ON } });
    mockGetFavicons.mockRejectedValueOnce(new Error('ipc down'));

    render(<Probe urls={['https://a.com']} />);
    await act(async () => {});

    expect(useAppStore.getState().faviconCache).toEqual({});
    expect(useAppStore.getState().faviconMisses).toEqual({});

    // A failure does not land in the negative cache → the next render retries naturally
    mockGetFavicons.mockResolvedValueOnce({
      success: true,
      data: [{ host: 'a.com', mime_type: 'image/png', data: 'AAA' }],
    });
    render(<Probe urls={['https://a.com']} />);
    await act(async () => {});
    expect(mockGetFavicons).toHaveBeenCalledTimes(2);
    expect(useAppStore.getState().faviconCache['a.com']).toBeDefined();
  });
});