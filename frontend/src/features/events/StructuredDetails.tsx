import { CodeBlock } from "../../components/CodeBlock";
import { KeyValueList, type KeyValueItem } from "../../components/KeyValueList";
import { revealInvisible } from "../../lib/text";
import { isRecord } from "../../lib/values";

export interface StructuredDetailsProps {
  /** Server-sanitised JSON object (event details, audit metadata). Treated as untrusted text. */
  value: unknown;
  /** Shown when there is nothing recorded. */
  emptyText: string;
  /** Caption of the raw JSON view. */
  rawLabel: string;
}

type Scalar = string | number | boolean | null;

function isScalar(value: unknown): value is Scalar {
  return value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function scalarItem(key: string, value: Scalar): KeyValueItem {
  return {
    key,
    term: <span className="break-all font-mono text-xs">{revealInvisible(key)}</span>,
    value: typeof value === "string" ? (value === "" ? "(empty)" : revealInvisible(value)) : typeof value === "number" ? String(value) : value,
    mono: typeof value !== "boolean",
  };
}

/**
 * A JSON object as plain text: top-level scalar values in a definition list, nested values and the
 * whole object in code blocks. Nothing is interpreted as markup or turned into a link.
 */
export function StructuredDetails({ value, emptyText, rawLabel }: StructuredDetailsProps) {
  if (!isRecord(value)) {
    if (value === null || value === undefined) return <p className="text-ink-muted">{emptyText}</p>;
    return <CodeBlock label={rawLabel} value={value} />;
  }
  const entries = Object.entries(value);
  if (entries.length === 0) return <p className="text-ink-muted">{emptyText}</p>;
  const scalars = entries.filter((entry): entry is [string, Scalar] => isScalar(entry[1]));
  const nested = entries.filter(([, entryValue]) => !isScalar(entryValue));
  return (
    <div className="flex min-w-0 flex-col gap-4">
      {scalars.length > 0 && <KeyValueList emptyText="null" items={scalars.map(([key, entryValue]) => scalarItem(key, entryValue))} />}
      {nested.map(([key, entryValue]) => (
        <CodeBlock key={key} label={revealInvisible(key)} value={entryValue} />
      ))}
      <details>
        <summary className="cursor-pointer text-xs text-ink-secondary hover:text-ink">{rawLabel}</summary>
        <CodeBlock className="mt-2" value={value} />
      </details>
    </div>
  );
}
