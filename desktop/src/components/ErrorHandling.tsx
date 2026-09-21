import * as React from 'react';
import { XCircleIcon, ExclamationTriangleIcon, InformationCircleIcon, CheckCircleIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { invoke } from '@tauri-apps/api/core';
import i18n from '@/i18n';

/**
 * production 前端错误落本地日志文件（Rust 侧脱敏 subscriber），上报失败
 * 静默——错误已经发生，上报路径不允许再制造二次噪声。
 */
const reportFrontendError = (
  message: string,
  stack: string | null,
  componentStack: string | null,
): void => {
  invoke('report_frontend_error', {
    message,
    stack,
    componentStack,
  }).catch(() => {});
};

interface ErrorBoundaryState {
  hasError: boolean;
  error?: Error;
  errorInfo?: React.ErrorInfo;
}

interface ErrorDisplayProps {
  error: string;
  type?: 'error' | 'warning' | 'info' | 'success';
  onDismiss?: () => void;
  details?: string;
}

export class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  ErrorBoundaryState
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
    this.setState({ error, errorInfo });

    if (process.env.NODE_ENV === 'production') {
      reportFrontendError(
        error.message,
        error.stack ?? null,
        errorInfo.componentStack ?? null,
      );
    }
  }

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-950 flex items-center justify-center p-4">
          <div className="max-w-md w-full bg-white dark:bg-gray-900 rounded-lg shadow-lg p-6">
            <div className="flex items-center mb-4">
              <XCircleIcon className="w-8 h-8 text-red-500 mr-3" />
              <h1 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
                {i18n.t('errorBoundary.title')}
              </h1>
            </div>

            <p className="text-gray-600 dark:text-gray-300 mb-4">
              {i18n.t('errorBoundary.description')}
            </p>

            {process.env.NODE_ENV === 'development' && this.state.error && (
              <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded-md p-3 mb-4">
                <p className="text-sm font-medium text-red-800 dark:text-red-300 mb-2">
                  {i18n.t('errorBoundary.devDetails')}
                </p>
                <pre className="text-xs text-red-700 dark:text-red-300 whitespace-pre-wrap">
                  {this.state.error.message}
                </pre>
              </div>
            )}

            <div className="flex space-x-3">
              <button
                onClick={this.handleReload}
                className="btn-primary flex-1"
              >
                {i18n.t('errorBoundary.reload')}
              </button>
              <button
                onClick={() => this.setState({ hasError: false })}
                className="btn-secondary flex-1"
              >
                {i18n.t('common.retry')}
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export const ErrorDisplay: React.FC<ErrorDisplayProps> = ({
  error,
  type = 'error',
  onDismiss,
  details,
}) => {
  const { t } = useTranslation();
  const getIcon = () => {
    switch (type) {
      case 'error':
        return <XCircleIcon className="w-5 h-5" />;
      case 'warning':
        return <ExclamationTriangleIcon className="w-5 h-5" />;
      case 'info':
        return <InformationCircleIcon className="w-5 h-5" />;
      case 'success':
        return <CheckCircleIcon className="w-5 h-5" />;
      default:
        return <XCircleIcon className="w-5 h-5" />;
    }
  };

  const getColorClasses = () => {
    switch (type) {
      case 'error':
        return 'bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/20 text-red-800 dark:text-red-300';
      case 'warning':
        return 'bg-yellow-50 dark:bg-yellow-500/10 border-yellow-200 dark:border-yellow-500/20 text-yellow-800 dark:text-yellow-300';
      case 'info':
        return 'bg-blue-50 dark:bg-blue-500/10 border-blue-200 dark:border-blue-500/20 text-blue-800 dark:text-blue-300';
      case 'success':
        return 'bg-green-50 dark:bg-green-500/10 border-green-200 dark:border-green-500/20 text-green-800 dark:text-green-300';
      default:
        return 'bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/20 text-red-800 dark:text-red-300';
    }
  };

  const getIconColorClass = () => {
    switch (type) {
      case 'error':
        return 'text-red-500';
      case 'warning':
        return 'text-yellow-500';
      case 'info':
        return 'text-blue-500';
      case 'success':
        return 'text-green-500';
      default:
        return 'text-red-500';
    }
  };

  return (
    <div className={`border rounded-md p-4 ${getColorClasses()}`}>
      <div className="flex">
        <div className={`flex-shrink-0 ${getIconColorClass()}`}>
          {getIcon()}
        </div>
        <div className="ml-3 flex-1">
          <p className="text-sm font-medium">{error}</p>
          {details && (
            <p className="text-sm mt-1 opacity-75">{details}</p>
          )}
        </div>
        {onDismiss && (
          <div className="ml-auto pl-3">
            <button
              onClick={onDismiss}
              className="inline-flex rounded-md p-1.5 hover:bg-black/10 dark:hover:bg-white/10 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-transparent"
            >
              <span className="sr-only">{t('common.dismiss')}</span>
              <XCircleIcon className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

// Hook for better error handling in components
export const useErrorHandler = () => {
  const [error, setError] = React.useState<string | null>(null);

  const handleError = React.useCallback((error: unknown, context?: string) => {
    console.error('Error in component:', error, context);

    let errorMessage = i18n.t('common.unexpectedError');

    if (error instanceof Error) {
      errorMessage = error.message;
    } else if (typeof error === 'string') {
      errorMessage = error;
    }

    if (process.env.NODE_ENV === 'production') {
      reportFrontendError(
        context ? `${context}: ${errorMessage}` : errorMessage,
        error instanceof Error ? error.stack ?? null : null,
        null,
      );
    }

    if (context) {
      errorMessage = `${context}: ${errorMessage}`;
    }

    setError(errorMessage);
  }, []);

  const clearError = React.useCallback(() => {
    setError(null);
  }, []);

  return { error, handleError, clearError };
};

// Utility function for API error handling
export const handleApiError = (error: unknown): string => {
  if (error && typeof error === 'object' && 'error' in error) {
    return (error as { error: string }).error;
  }

  if (error instanceof Error) {
    return error.message;
  }

  if (typeof error === 'string') {
    return error;
  }

  return i18n.t('common.unexpectedError');
};

// Loading state component
export const LoadingSpinner: React.FC<{ message?: string }> = ({
  message,
}) => {
  const { t } = useTranslation();
  return (
    <div className="flex items-center justify-center p-4">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mr-3"></div>
      <span className="text-gray-600 dark:text-gray-300">{message ?? t('common.loading')}</span>
    </div>
  );
};

// Empty state component
export const EmptyState: React.FC<{
  title: string;
  description: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}> = ({ title, description, action }) => (
  <div className="text-center py-12">
    <div className="mx-auto w-24 h-24 bg-gray-100 dark:bg-gray-800 rounded-full flex items-center justify-center mb-4">
      <InformationCircleIcon className="w-12 h-12 text-gray-400 dark:text-gray-500" />
    </div>
    <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">{title}</h3>
    <p className="text-gray-500 dark:text-gray-400 mb-6 max-w-sm mx-auto">{description}</p>
    {action && (
      <button onClick={action.onClick} className="btn-primary">
        {action.label}
      </button>
    )}
  </div>
);
