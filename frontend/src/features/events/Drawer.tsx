import { useEffect, useId, useLayoutEffect, useRef, type KeyboardEvent, type ReactNode } from "react";
import { createPortal } from "react-dom";

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])';

export interface DrawerProps {
  open: boolean;
  /** Visible heading and accessible name of the dialog. */
  title: ReactNode;
  description?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  /** Actions pinned to the bottom of the panel. */
  footer?: ReactNode;
  /**
   * Where focus goes after closing when the element that opened the drawer is gone (for example a
   * row that a refresh removed).
   */
  fallbackFocus?: () => HTMLElement | null;
}

/**
 * Modal side panel for record details. Focus moves to its heading, Tab and Shift+Tab stay inside,
 * Escape, the Close button or a click on the backdrop closes it, and focus returns to the opener.
 */
export function Drawer(props: DrawerProps) {
  if (!props.open) return null;
  return createPortal(<DrawerPanel {...props} />, document.body);
}

function DrawerPanel({ title, description, onClose, children, footer, fallbackFocus }: DrawerProps) {
  const titleId = useId();
  const descriptionId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const fallbackRef = useRef(fallbackFocus);
  useLayoutEffect(() => {
    fallbackRef.current = fallbackFocus;
  });

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const fallback = fallbackRef;
    const body = document.body;
    const previousOverflow = body.style.overflow;
    body.style.overflow = "hidden";
    headingRef.current?.focus();
    return () => {
      body.style.overflow = previousOverflow;
      if (opener?.isConnected && opener !== body) opener.focus();
      else fallback.current?.()?.focus();
    };
  }, []);

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape") {
      event.stopPropagation();
      onClose();
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
    const atStart = active === first || active === headingRef.current || !panelRef.current?.contains(active);
    if (event.shiftKey && atStart) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || !panelRef.current?.contains(active))) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <div
      className="fixed inset-0 z-40 flex justify-end bg-black/50"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        onKeyDown={onKeyDown}
        className="flex h-full w-full max-w-2xl flex-col border-l border-line-strong bg-panel shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="min-w-0">
            <h2
              id={titleId}
              ref={headingRef}
              tabIndex={-1}
              className="wrap-break-word font-condensed text-xl font-semibold leading-tight text-ink focus:outline-hidden"
            >
              {title}
            </h2>
            {description && (
              <div id={descriptionId} className="mt-1 text-xs text-ink-secondary">
                {description}
              </div>
            )}
          </div>
          <button type="button" className="btn-ghost shrink-0" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
        {footer && <div className="border-t border-line px-5 py-3">{footer}</div>}
      </div>
    </div>
  );
}
