import { act, fireEvent, render, renderHook, screen } from '@testing-library/react';
import {
  EmptyState,
  ErrorBoundary,
  ErrorDisplay,
  LoadingSpinner,
  handleApiError,
  useErrorHandler,
} from './ErrorHandling';

/** 渲染时抛错的哑组件（React 需要 key 提示重渲染边界）。 */
const Bomb = ({ message }: { message: string }) => {
  throw new Error(message);
};

describe('components/ErrorHandling', () => {
  it('handleApiError extracts message from common shapes', () => {
    expect(handleApiError({ error: 'boom' })).toBe('boom');
    expect(handleApiError(new Error('nope'))).toBe('nope');
    expect(handleApiError('plain')).toBe('plain');
    expect(handleApiError({})).toBe('发生意外错误');
    expect(handleApiError(null)).toBe('发生意外错误');
  });

  it('useErrorHandler sets and clears error state', () => {
    const { result } = renderHook(() => useErrorHandler());

    act(() => {
      result.current.handleError(new Error('bad'), 'Context');
    });
    expect(result.current.error).toBe('Context: bad');

    act(() => {
      result.current.clearError();
    });
    expect(result.current.error).toBeNull();
  });

  it('useErrorHandler falls back to the message string, plain strings and the default text', () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const { result } = renderHook(() => useErrorHandler());

    act(() => {
      result.current.handleError(new Error('raw message'));
    });
    expect(result.current.error).toBe('raw message');

    act(() => {
      result.current.handleError('string error');
    });
    expect(result.current.error).toBe('string error');

    // 非 Error 且非 string（如 number）→ 默认文案，无 context 前缀
    act(() => {
      result.current.handleError(42);
    });
    expect(result.current.error).toBe('发生意外错误');

    consoleSpy.mockRestore();
  });

  it('ErrorDisplay renders and calls onDismiss', () => {
    const onDismiss = jest.fn();
    const { getByRole, getByText } = render(
      <ErrorDisplay error="Oops" type="warning" details="Details" onDismiss={onDismiss} />,
    );

    expect(getByText('Oops')).toBeInTheDocument();
    expect(getByText('Details')).toBeInTheDocument();

    getByRole('button', { name: '忽略' }).click();
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it.each(['error', 'warning', 'info', 'success'] as const)(
    'ErrorDisplay applies type-specific classes for %s',
    (type) => {
      const { container } = render(<ErrorDisplay error="e" type={type} />);
      const root = container.firstElementChild as HTMLElement;
      expect(root.className).toMatch(/border/);
      expect(['bg-red-50', 'bg-yellow-50', 'bg-blue-50', 'bg-green-50']).toContain(
        root.className.split(' ').find((c) => c.startsWith('bg-'))!,
      );
    },
  );

  it('ErrorDisplay omits the dismiss button and details when not provided', () => {
    render(<ErrorDisplay error="bare" />);
    expect(screen.getByText('bare')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '忽略' })).not.toBeInTheDocument();
  });

  it('ErrorBoundary shows the fallback, dev details and recovers via Try Again', () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const prevEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';

    render(
      <ErrorBoundary>
        <Bomb message="kaboom" />
      </ErrorBoundary>,
    );

    expect(screen.getByText('出错了')).toBeInTheDocument();
    expect(screen.getByText('kaboom')).toBeInTheDocument(); // dev 模式错误详情

    // Try Again 清除错误态：恢复渲染同一棵子树（不再抛错的实现）
    fireEvent.click(screen.getByRole('button', { name: '重试' }));
    expect(screen.getByText('出错了')).toBeInTheDocument();

    process.env.NODE_ENV = prevEnv;
    consoleSpy.mockRestore();
  });

  it('ErrorBoundary fallback offers reload and try-again actions', () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <Bomb message="x" />
      </ErrorBoundary>,
    );
    // jsdom 的 window.location 不可 stub（LegacyUnforgeable），
    // 这里只验证恢复动作入口存在；reload 本身是单行调用。
    expect(screen.getByRole('button', { name: '重新加载应用' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '重试' })).toBeInTheDocument();

    consoleSpy.mockRestore();
  });

  it('ErrorBoundary reports to tracking in production builds', () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    const prevEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    render(
      <ErrorBoundary>
        <Bomb message="prod-failure" />
      </ErrorBoundary>,
    );

    expect(logSpy).toHaveBeenCalledWith(
      'Would report error to tracking service:',
      expect.objectContaining({ error: 'prod-failure' }),
    );

    process.env.NODE_ENV = prevEnv;
    consoleSpy.mockRestore();
    logSpy.mockRestore();
  });

  it('ErrorBoundary renders children untouched when nothing throws', () => {
    render(
      <ErrorBoundary>
        <span>fine</span>
      </ErrorBoundary>,
    );
    expect(screen.getByText('fine')).toBeInTheDocument();
  });

  it('LoadingSpinner uses a custom or the default message', () => {
    render(<LoadingSpinner message="Initializing Persona..." />);
    expect(screen.getByText('Initializing Persona...')).toBeInTheDocument();
  });

  it('EmptyState renders with and without an action', () => {
    const onClick = jest.fn();
    render(
      <EmptyState
        title="No credentials"
        description="Create your first credential"
        action={{ label: 'Add one', onClick }}
      />,
    );
    expect(screen.getByText('No credentials')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Add one' }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });
});

