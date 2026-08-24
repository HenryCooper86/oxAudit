import { AlertTriangle, LayoutDashboard, RotateCcw } from "lucide-react";
import { Component, type ErrorInfo, type ReactNode } from "react";

interface PageErrorBoundaryProps {
  children: ReactNode;
  resetKey: string;
  onReturnHome: () => void;
}

interface PageErrorBoundaryState {
  failed: boolean;
}

/** Keeps one broken workspace from taking down the desktop application shell. */
export class PageErrorBoundary extends Component<
  PageErrorBoundaryProps,
  PageErrorBoundaryState
> {
  state: PageErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): PageErrorBoundaryState {
    return { failed: true };
  }

  componentDidCatch(error: unknown, info: ErrorInfo) {
    console.error("Workspace render failed", error, info.componentStack);
  }

  componentDidUpdate(previous: PageErrorBoundaryProps) {
    if (previous.resetKey !== this.props.resetKey && this.state.failed) {
      this.setState({ failed: false });
    }
  }

  private returnHome = () => {
    this.setState({ failed: false });
    this.props.onReturnHome();
  };

  render() {
    if (!this.state.failed) return this.props.children;

    return (
      <section
        aria-labelledby="workspace-error-title"
        className="mx-auto flex min-h-full max-w-xl items-center px-6 py-12"
      >
        <div className="w-full rounded-sm border border-error-border bg-surface-secondary p-5">
          <div className="flex items-start gap-3">
            <AlertTriangle
              aria-hidden="true"
              className="mt-0.5 shrink-0 text-error"
              size={18}
            />
            <div>
              <h1
                id="workspace-error-title"
                className="text-[14px] font-semibold text-text-primary"
              >
                This workspace could not be displayed
              </h1>
              <p className="mt-1 text-[13px] leading-5 text-text-muted">
                Your saved runs and settings are untouched. Return to the dashboard,
                or reload oxAudit if the problem continues.
              </p>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-2 pl-[30px]">
            <button
              type="button"
              onClick={this.returnHome}
              className="inline-flex items-center gap-1.5 rounded-sm border border-border bg-surface-tertiary px-3 py-1.5 text-[12px] font-medium text-text-primary transition-colors hover:border-border-strong hover:bg-surface-active"
            >
              <LayoutDashboard aria-hidden="true" size={13} />
              Return to dashboard
            </button>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="inline-flex items-center gap-1.5 rounded-sm border border-border bg-transparent px-3 py-1.5 text-[12px] font-medium text-text-secondary transition-colors hover:bg-surface-hover hover:text-text-primary"
            >
              <RotateCcw aria-hidden="true" size={13} />
              Reload oxAudit
            </button>
          </div>
        </div>
      </section>
    );
  }
}
