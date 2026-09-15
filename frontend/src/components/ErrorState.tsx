import type { ApiError } from "../api/client";

export interface ErrorStateProps {
  error: ApiError | string;
  title?: string;
  onRetry?: () => void;
  /** Label of the retry button. */
  retryLabel?: string;
}

/** What failed, the server's explanation, and the request id to quote when reporting it. */
export function ErrorState({ error, title = "This data could not be loaded", onRetry, retryLabel = "Try again" }: ErrorStateProps) {
  const info: ApiError = typeof error === "string" ? { status: null, code: null, message: error, requestId: null } : error;
  return (
    <div role="alert" className="flex flex-col items-start gap-1 rounded-r-md border-l-2 border-sev-critical bg-sunken px-4 py-3">
      <p className="font-medium text-ink">{title}</p>
      <p className="break-words text-ink-secondary">{info.message}</p>
      {(info.status !== null || info.requestId) && (
        <p className="text-xs text-ink-muted">
          {info.status !== null && <span>HTTP {info.status}</span>}
          {info.status !== null && info.requestId && ", "}
          {info.requestId && (
            <span>
              request id <code className="font-mono">{info.requestId}</code>
            </span>
          )}
        </p>
      )}
      {onRetry && (
        <button type="button" className="btn-secondary mt-2" onClick={onRetry}>
          {retryLabel}
        </button>
      )}
    </div>
  );
}
