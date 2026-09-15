import { Component, type ReactNode } from "react";
import { isChunkLoadError } from "../lib/errors";
import { ErrorState } from "./ErrorState";

export interface RouteErrorBoundaryProps {
  children: ReactNode;
  /** A shown error is cleared when this value changes (pass the route path). */
  resetKey?: unknown;
  /** Reloads the page. Defaults to window.location.reload; injectable for tests. */
  onReload?: () => void;
}

interface RouteErrorBoundaryState {
  hasError: boolean;
  error: unknown;
}

/**
 * Catches errors thrown while rendering a view, including a lazily loaded route whose chunk no longer
 * exists after a redeploy. Without a boundary React unmounts the whole application and leaves an
 * empty page. The rest of the console (navigation, sign-out) stays usable, and a reload recovers:
 * React keeps a failed lazy import failed for the lifetime of the page.
 */
export class RouteErrorBoundary extends Component<RouteErrorBoundaryProps, RouteErrorBoundaryState> {
  state: RouteErrorBoundaryState = { hasError: false, error: null };

  static getDerivedStateFromError(error: unknown): RouteErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidUpdate(previous: RouteErrorBoundaryProps) {
    if (this.state.hasError && !Object.is(previous.resetKey, this.props.resetKey)) {
      this.setState({ hasError: false, error: null });
    }
  }

  render() {
    if (!this.state.hasError) return this.props.children;
    const reload = this.props.onReload ?? (() => window.location.reload());
    const chunkMissing = isChunkLoadError(this.state.error);
    return (
      <ErrorState
        title={chunkMissing ? "This view could not be loaded" : "This view failed to display"}
        error={
          chunkMissing
            ? "The console has probably been updated since this page was opened. Reload the page to get the current version."
            : "An unexpected error stopped this view from rendering. Reloading the page usually recovers; if it keeps happening, tell your Warden administrator what you were doing."
        }
        onRetry={reload}
        retryLabel="Reload page"
      />
    );
  }
}
