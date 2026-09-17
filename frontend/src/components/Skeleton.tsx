export function Skeleton({ className = "" }: { className?: string }) {
  return <span aria-hidden="true" className={`block animate-pulse rounded-sm bg-raised ${className}`} />;
}

export interface LoadingBlockProps {
  /** Announced to screen readers while loading. */
  label?: string;
  rows?: number;
}

/** Placeholder rows with a polite live status, for first loads only (refetches keep old data). */
export function LoadingBlock({ label = "Loading", rows = 3 }: LoadingBlockProps) {
  return (
    <div role="status" aria-live="polite" className="flex flex-col gap-2 py-2">
      <span className="sr-only">{label}</span>
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton key={index} className={`h-4 ${index % 3 === 2 ? "w-2/3" : "w-full"}`} />
      ))}
    </div>
  );
}
