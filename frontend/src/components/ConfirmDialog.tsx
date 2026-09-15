import { useEffect, useId, useRef, type KeyboardEvent, type ReactNode } from "react";
import { createPortal } from "react-dom";

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description?: ReactNode;
  /** Extra content such as a comment field. */
  children?: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  tone?: "default" | "danger";
  /** While true the confirm button ignores clicks and Escape does not close the dialog. */
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Modal confirmation for consequential actions. Focus moves to the cancel button (the safe
 * choice), Tab and Shift+Tab stay inside the dialog, Escape or a click on the backdrop cancels,
 * and focus returns to the element that opened it.
 */
export function ConfirmDialog(props: ConfirmDialogProps) {
  if (!props.open) return null;
  return createPortal(<DialogPanel {...props} />, document.body);
}

function DialogPanel({
  title,
  description,
  children,
  confirmLabel,
  cancelLabel = "Cancel",
  tone = "default",
  busy = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const titleId = useId();
  const descriptionId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    cancelRef.current?.focus();
    return () => {
      // The opener can be gone by now (for example a row action whose row changed). Callers that
      // remove the opener should move focus somewhere meaningful themselves once the dialog closes.
      if (previouslyFocused?.isConnected) previouslyFocused.focus();
    };
  }, []);

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape") {
      event.stopPropagation();
      if (!busy) onCancel();
      return;
    }
    if (event.key !== "Tab") return;
    const focusable = Array.from(panelRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []);
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (!first || !last) {
      event.preventDefault();
      return;
    }
    const active = document.activeElement;
    const outside = !panelRef.current?.contains(active);
    if (event.shiftKey && (active === first || outside)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || outside)) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onCancel();
      }}
    >
      <div
        ref={panelRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        onKeyDown={onKeyDown}
        className="w-full max-w-md rounded-md border border-line-strong bg-panel p-5 shadow-2xl"
      >
        <h2 id={titleId} className="font-condensed text-xl font-semibold text-ink">
          {title}
        </h2>
        {description && (
          <div id={descriptionId} className="mt-2 text-ink-secondary">
            {description}
          </div>
        )}
        {children && <div className="mt-4">{children}</div>}
        <div className="mt-5 flex justify-end gap-2">
          <button ref={cancelRef} type="button" className="btn-secondary" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button
            type="button"
            className={tone === "danger" ? "btn-danger" : "btn-primary"}
            aria-disabled={busy || undefined}
            onClick={() => {
              if (!busy) onConfirm();
            }}
          >
            {busy ? "Working" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
