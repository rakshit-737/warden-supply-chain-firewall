import { useId, useState, type ReactNode } from "react";

export interface TooltipTriggerProps {
  "aria-describedby": string | undefined;
}

export interface TooltipProps {
  content: ReactNode;
  /** Render the trigger and spread the props onto its focusable element. */
  children: (trigger: TooltipTriggerProps) => ReactNode;
  placement?: "top" | "bottom";
}

/**
 * Short supplementary text shown on hover and on keyboard focus, dismissible with Escape. Never
 * put information only here: tooltips are unreachable on touch screens.
 */
export function Tooltip({ content, children, placement = "top" }: TooltipProps) {
  const id = useId();
  const [open, setOpen] = useState(false);
  return (
    <span
      className="relative inline-flex"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      onKeyDown={(event) => {
        if (event.key === "Escape" && open) {
          event.stopPropagation();
          setOpen(false);
        }
      }}
    >
      {children({ "aria-describedby": open ? id : undefined })}
      {open && (
        <span
          role="tooltip"
          id={id}
          className={`pointer-events-none absolute left-1/2 z-30 w-max max-w-xs -translate-x-1/2 rounded border border-line-strong bg-raised px-2 py-1 text-xs text-ink shadow-lg ${
            placement === "top" ? "bottom-full mb-1.5" : "top-full mt-1.5"
          }`}
        >
          {content}
        </span>
      )}
    </span>
  );
}
