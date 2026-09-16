export interface InvalidParamsNoticeProps {
  /** Human-readable names of the query parameters that were ignored. */
  labels: string[];
  onRemove: () => void;
}

/** Says that some filters in the address were not valid and therefore not sent to the server. */
export function InvalidParamsNotice({ labels, onRemove }: InvalidParamsNoticeProps) {
  if (labels.length === 0) return null;
  return (
    <div
      role="status"
      className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-r-md border-l-2 border-verdict-warn bg-panel px-4 py-2 text-ink-secondary"
    >
      <span>This address contains filters that are not valid, so they were not applied: {labels.join(", ")}.</span>
      <button type="button" className="btn-ghost h-7 px-2" onClick={onRemove}>
        Remove them
      </button>
    </div>
  );
}
