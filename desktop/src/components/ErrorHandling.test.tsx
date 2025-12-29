import React from 'react';
import { act, render, renderHook } from '@testing-library/react';
import { ErrorDisplay, handleApiError, useErrorHandler } from './ErrorHandling';

describe('components/ErrorHandling', () => {
  it('handleApiError extracts message from common shapes', () => {
    expect(handleApiError({ error: 'boom' })).toBe('boom');
    expect(handleApiError(new Error('nope'))).toBe('nope');
    expect(handleApiError('plain')).toBe('plain');
    expect(handleApiError({})).toBe('An unexpected error occurred');
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

  it('ErrorDisplay renders and calls onDismiss', () => {
    const onDismiss = jest.fn();
    const { getByRole, getByText } = render(
      <ErrorDisplay error="Oops" type="warning" details="Details" onDismiss={onDismiss} />,
    );

    expect(getByText('Oops')).toBeInTheDocument();
    expect(getByText('Details')).toBeInTheDocument();

    getByRole('button', { name: 'Dismiss' }).click();
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });
});

