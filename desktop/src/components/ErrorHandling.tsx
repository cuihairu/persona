import React from 'react';
import { XCircleIcon, ExclamationTriangleIcon, InformationCircleIcon, CheckCircleIcon } from '@heroicons/react/24/outline';

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

    // Report to error tracking service in production
    if (process.env.NODE_ENV === 'production') {
      // TODO: Send error to tracking service
      console.log('Would report error to tracking service:', {
        error: error.message,
        stack: error.stack,
        componentStack: errorInfo.componentStack,
      });
    }
  }

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
          <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-6">
            <div className="flex items-center mb-4">
              <XCircleIcon className="w-8 h-8 text-red-500 mr-3" />
              <h1 className="text-xl font-semibold text-gray-900">
                Something went wrong
              </h1>
            </div>

            <p className="text-gray-600 mb-4">
              An unexpected error occurred. This might be a temporary issue.
            </p>

            {process.env.NODE_ENV === 'development' && this.state.error && (
              <div className="bg-red-50 border border-red-200 rounded-md p-3 mb-4">
                <p className="text-sm font-medium text-red-800 mb-2">
                  Error Details (Development):
                </p>
                <pre className="text-xs text-red-700 whitespace-pre-wrap">
                  {this.state.error.message}
                </pre>
              </div>
            )}

            <div className="flex space-x-3">
              <button
                onClick={this.handleReload}
                className="btn-primary flex-1"
              >
                Reload Application
              </button>
              <button
                onClick={() => this.setState({ hasError: false })}
                className="btn-secondary flex-1"
              >
                Try Again
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
        return 'bg-red-50 border-red-200 text-red-800';
      case 'warning':
        return 'bg-yellow-50 border-yellow-200 text-yellow-800';
      case 'info':
        return 'bg-blue-50 border-blue-200 text-blue-800';
      case 'success':
        return 'bg-green-50 border-green-200 text-green-800';
      default:
        return 'bg-red-50 border-red-200 text-red-800';
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
              className="inline-flex rounded-md p-1.5 hover:bg-black hover:bg-opacity-10 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-transparent"
            >
              <span className="sr-only">Dismiss</span>
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

    let errorMessage = 'An unexpected error occurred';

    if (error instanceof Error) {
      errorMessage = error.message;
    } else if (typeof error === 'string') {
      errorMessage = error;
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

  return 'An unexpected error occurred';
};

// Loading state component
export const LoadingSpinner: React.FC<{ message?: string }> = ({ message = 'Loading...' }) => (
  <div className="flex items-center justify-center p-4">
    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mr-3"></div>
    <span className="text-gray-600">{message}</span>
  </div>
);

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
    <div className="mx-auto w-24 h-24 bg-gray-100 rounded-full flex items-center justify-center mb-4">
      <InformationCircleIcon className="w-12 h-12 text-gray-400" />
    </div>
    <h3 className="text-lg font-medium text-gray-900 mb-2">{title}</h3>
    <p className="text-gray-500 mb-6 max-w-sm mx-auto">{description}</p>
    {action && (
      <button onClick={action.onClick} className="btn-primary">
        {action.label}
      </button>
    )}
  </div>
);