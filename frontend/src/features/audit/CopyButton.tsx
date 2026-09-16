import { useState } from "react";

/** Copies a value to the clipboard and says whether that worked. */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  async function copy() {
    try {
      if (typeof navigator === "undefined" || !("clipboard" in navigator)) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      setState("failed");
    }
  }

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <button type="button" className="btn-ghost h-7 px-2" onClick={() => void copy()}>
        Copy <span className="sr-only">{label}</span>
      </button>
      <span role="status" className="text-xs text-ink-muted">
        {state === "copied" ? "Copied" : state === "failed" ? "Could not copy. Select the text and copy it instead." : ""}
      </span>
    </span>
  );
}
