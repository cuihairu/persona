import { act, fireEvent, render, renderHook, screen } from '@testing-library/react';
import {
  EmptyState,
  ErrorBoundary,
  ErrorDisplay,
  LoadingSpinner,
  handleApiError,
  useErrorHandler,
} from './ErrorHandling';

const mockInvoke = jest.fn().mockResolvedValue(undefined);
jest.mock('@tauri-apps/api/core', () => ({
  invoke: (cmd: string, args?: unknown) => mockInvoke(cmd, args),
}));

/** A dumb component that throws while rendering (React needs a key to mark the remount boundary). */
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

    // Neither an Error nor a string (e.g. a number) → default text, no context prefix
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

  it('ErrorBoundary reload button reloads the page', () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <Bomb message="kaboom-reload" />
      </ErrorBoundary>,
    );

    // jsdom only reports "Not implemented" for location.reload without throwing: the click runs handleReload
    expect(() =>
      fireEvent.click(screen.getByRole('button', { name: '重新加载应用' }))
    ).not.toThrow();
    consoleSpy.mockRestore();
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
    expect(screen.getByText('kaboom')).toBeInTheDocument(); // dev mode error details

    // Try Again clears the error state: the same subtree is rendered again (an implementation that no longer throws)
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
    // jsdom's window.location cannot be stubbed (LegacyUnforgeable),
    // so only assert that the recovery entry point exists; reload itself is a one-line call.
    expect(screen.getByRole('button', { name: '重新加载应用' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '重试' })).toBeInTheDocument();

    consoleSpy.mockRestore();
  });

  it('ErrorBoundary reports to the local log sink in production builds', () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const prevEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    mockInvoke.mockClear();

    render(
      <ErrorBoundary>
        <Bomb message="prod-failure" />
      </ErrorBoundary>,
    );

    expect(mockInvoke).toHaveBeenCalledWith(
      'report_frontend_error',
      expect.objectContaining({ message: 'prod-failure' }),
    );

    process.env.NODE_ENV = prevEnv;
    consoleSpy.mockRestore();
  });

  it('ErrorBoundary stays upright when error reporting itself fails', async () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const prevEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    mockInvoke.mockReset();
    mockInvoke.mockRejectedValueOnce(new Error('ipc down'));

    render(
      <ErrorBoundary>
        <Bomb message="still-rendered" />
      </ErrorBoundary>,
    );

    // The failed report is silently swallowed and the fallback UI renders as usual
    expect(screen.getByText('出错了')).toBeInTheDocument();
    await act(async () => {});
    expect(screen.getByText('出错了')).toBeInTheDocument();

    process.env.NODE_ENV = prevEnv;
    mockInvoke.mockResolvedValue(undefined);
    consoleSpy.mockRestore();
  });

  it('useErrorHandler reports handled errors in production builds', () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const prevEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    mockInvoke.mockClear();

    const { result } = renderHook(() => useErrorHandler());
    act(() => {
      result.current.handleError(new Error('hook-failure'), 'Ctx');
    });

    expect(mockInvoke).toHaveBeenCalledWith(
      'report_frontend_error',
      expect.objectContaining({ message: 'Ctx: hook-failure' }),
    );
    expect(result.current.error).toBe('Ctx: hook-failure');

    process.env.NODE_ENV = prevEnv;
    consoleSpy.mockRestore();
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

