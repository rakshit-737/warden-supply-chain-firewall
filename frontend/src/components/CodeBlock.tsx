import { formatCount } from "../lib/format";
import { revealInvisible, toDisplayText, truncateText } from "../lib/text";

const DEFAULT_MAX_CHARS = 20_000;

export interface CodeBlockProps {
  /** Strings are shown as-is; anything else is pretty-printed JSON. */
  value: unknown;
  label?: string;
  maxChars?: number;
  className?: string;
}

/**
 * Shows untrusted text (evidence, snippets, manifests) exactly as plain text. The content is a
 * React text child, so markup in it is escaped rather than parsed; invisible and bidirectional
 * control characters are replaced by visible <U+XXXX> markers; long lines wrap.
 */
export function CodeBlock({ value, label, maxChars = DEFAULT_MAX_CHARS, className = "" }: CodeBlockProps) {
  const full = toDisplayText(value);
  const { text, truncated } = truncateText(full, maxChars);
  return (
    <figure className={`min-w-0 ${className}`}>
      {label && <figcaption className="mb-1 text-xs text-ink-secondary">{label}</figcaption>}
      <pre
        tabIndex={0}
        className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded border border-line bg-sunken p-3 font-mono text-xs leading-relaxed text-ink [overflow-wrap:anywhere]"
      >
        <code>{revealInvisible(text)}</code>
      </pre>
      {truncated && (
        <p className="mt-1 text-xs text-ink-muted">
          Showing the first {formatCount(text.length)} of {formatCount(full.length)} characters.
        </p>
      )}
    </figure>
  );
}
