import type { Ref } from "react";

export interface FilterTextFieldProps {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  /** Validation message; marks the input invalid and describes it. */
  error?: string;
  hint?: string;
  inputRef?: Ref<HTMLInputElement>;
  type?: "text" | "search" | "datetime-local";
  maxLength?: number;
  placeholder?: string;
  /** id of a <datalist> with suggestions. */
  list?: string;
  mono?: boolean;
  className?: string;
}

/** Labelled filter input whose error is programmatically tied to it (aria-invalid, aria-describedby). */
export function FilterTextField({
  id,
  label,
  value,
  onChange,
  error,
  hint,
  inputRef,
  type = "text",
  maxLength,
  placeholder,
  list,
  mono = false,
  className = "",
}: FilterTextFieldProps) {
  const errorId = `${id}-error`;
  const hintId = `${id}-hint`;
  const describedBy = [error ? errorId : null, hint ? hintId : null].filter(Boolean).join(" ") || undefined;
  return (
    <div className={className}>
      <label htmlFor={id} className="label">
        {label}
      </label>
      <input
        id={id}
        ref={inputRef}
        type={type}
        className={`input ${mono ? "font-mono" : ""} ${error ? "border-sev-critical" : ""}`}
        value={value}
        maxLength={maxLength}
        placeholder={placeholder}
        list={list}
        autoComplete="off"
        spellCheck={false}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        onChange={(event) => onChange(event.target.value)}
      />
      {error && (
        <p id={errorId} className="mt-1 flex items-start gap-1.5 text-xs text-ink">
          <span aria-hidden="true" className="mt-[0.3rem] h-1.5 w-1.5 shrink-0 rounded-full bg-sev-critical" />
          {error}
        </p>
      )}
      {hint && (
        <p id={hintId} className="mt-1 text-xs text-ink-muted">
          {hint}
        </p>
      )}
    </div>
  );
}

/** Announces that a filter submission was refused; the fields carry the specific messages. */
export function FilterErrorSummary({ count }: { count: number }) {
  if (count === 0) return null;
  return (
    <p role="alert" className="rounded-r border-l-2 border-sev-critical bg-sunken px-3 py-2 text-ink">
      The filters were not applied. {count === 1 ? "Correct the highlighted field." : `Correct the ${count} highlighted fields.`}
    </p>
  );
}
