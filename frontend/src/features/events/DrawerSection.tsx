import { useId, type ReactNode } from "react";

/** A labelled group inside a detail drawer. */
export function DrawerSection({ title, children }: { title: string; children: ReactNode }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className="flex min-w-0 flex-col gap-2">
      <h3 id={id} className="text-xs font-semibold uppercase tracking-wide text-ink-secondary">
        {title}
      </h3>
      {children}
    </section>
  );
}
