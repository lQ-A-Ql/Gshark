import { Component, type ErrorInfo, type PropsWithChildren, type ReactNode } from "react";

interface ErrorBoundaryProps extends PropsWithChildren {
  fallback?: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("ErrorBoundary caught an error:", error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }
      return (
        <div className="meow-page-bg flex h-screen w-screen flex-col items-center justify-center p-6 text-slate-900">
          <div className="meow-tile meow-workbench-panel max-w-md space-y-4 px-6 py-5">
            <h1 className="text-lg font-semibold text-rose-600">界面出现错误</h1>
            <p className="text-sm text-slate-600">
              应用渲染时发生未捕获的错误。请刷新页面重试，或联系支持团队。
            </p>
            {this.state.error?.message && (
              <pre className="max-h-40 overflow-auto rounded bg-slate-100 p-3 text-xs text-slate-700">
                {this.state.error.message}
              </pre>
            )}
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="meow-control-primary w-full px-4 py-2 text-sm font-medium"
            >
              刷新页面
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
