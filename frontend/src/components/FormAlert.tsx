import type { ReactNode } from "react";

/** Inline validation message for a form (announced to assistive technology). */
export function FormAlert({ children }: { children: ReactNode }) {
  return (
    <p role="alert" className="rounded-r border-l-2 border-sev-critical bg-sunken px-3 py-2 text-ink">
      {children}
    </p>
  );
}
