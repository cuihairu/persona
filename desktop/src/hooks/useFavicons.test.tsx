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

/** 极简探针：把 faviconFor 的返回值渲染出来 */
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
    // flag 关：不请求、faviconFor 恒 null
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
    // 归一去重：a.com 大小写合并；null 丢弃；排序稳定
    expect(mockGetFavicons).toHaveBeenCalledWith(['a.com', 'b.com']);

    // 命中进缓存；缺席落负缓存
    expect(useAppStore.getState().faviconCache['a.com']).toEqual({
      mime_type: 'image/png',
      data: 'AAA',
    });
    expect(useAppStore.getState().faviconMisses).toEqual({ 'b.com': true });
    expect(readProbe(container, 0)).toContain('"data":"AAA"');
    expect(readProbe(container, 2)).toBe('null');

    // 再次渲染（同 hosts）：命中与负缓存都不再请求
    mockGetFavicons.mockClear();
    rerender(<Probe urls={urls} />);
    await act(async () => {});
    expect(mockGetFavicons).not.toHaveBeenCalled();

    // faviconFor 对缺失 url 恒 null
    expect(readProbe(container, 3)).toBe('null');
  });

  it('does not flag misses when the batch read fails', async () => {
    useAppStore.setState({ featureFlags: { ...FLAG_ON } });
    mockGetFavicons.mockRejectedValueOnce(new Error('ipc down'));

    render(<Probe urls={['https://a.com']} />);
    await act(async () => {});

    expect(useAppStore.getState().faviconCache).toEqual({});
    expect(useAppStore.getState().faviconMisses).toEqual({});

    // 失败未落负缓存 → 下一次渲染自然重试
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
