/** "Drift" / "No drift" with a shape marker, so the result does not rely on colour alone. */
export function DriftLabel({ drift }: { drift: boolean }) {
  return drift ? (
    <span className="inline-flex items-center gap-1.5 font-semibold text-ink">
      <span aria-hidden className="h-2 w-2 rotate-45 bg-sev-high" />
      Drift
    </span>
  ) : (
    <span className="text-ink-secondary">No drift</span>
  );
}
