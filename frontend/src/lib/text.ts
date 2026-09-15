/**
 * Code points that change how text displays without being visible: C0/C1 control characters
 * (except tab, line feed and carriage return), bidirectional overrides and isolates ("Trojan
 * Source", CVE-2021-42574), zero-width characters, invisible fillers, the BOM and Unicode tag
 * characters. The backend escapes these in evidence already; this is a second, display-side
 * layer for attacker-controlled text.
 */
function isInvisible(cp: number): boolean {
  return (
    (cp <= 0x1f && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) ||
    (cp >= 0x7f && cp <= 0x9f) ||
    cp === 0xad ||
    cp === 0x61c ||
    cp === 0x115f ||
    cp === 0x1160 ||
    cp === 0x180e ||
    (cp >= 0x200b && cp <= 0x200f) ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x2064) ||
    (cp >= 0x2066 && cp <= 0x2069) ||
    cp === 0x3164 ||
    cp === 0xfeff ||
    cp === 0xffa0 ||
    (cp >= 0xe0000 && cp <= 0xe007f)
  );
}

/** Replace invisible and bidirectional control characters with a visible `<U+XXXX>` marker. */
export function revealInvisible(text: string): string {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    out += isInvisible(cp) ? `<U+${cp.toString(16).toUpperCase().padStart(4, "0")}>` : ch;
  }
  return out;
}

function fallbackText(value: unknown): string {
  switch (typeof value) {
    case "number":
    case "boolean":
    case "bigint":
    case "symbol":
      return value.toString();
    case "function":
      return "[function]";
    default:
      return "[value that cannot be displayed as JSON]";
  }
}

/**
 * Serialise an arbitrary value for plain-text display. Strings pass through; everything else is
 * pretty-printed JSON. Never throws: circular structures and other values JSON cannot represent
 * get a textual fallback.
 */
export function toDisplayText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined) return "";
  try {
    return JSON.stringify(value, null, 2) ?? fallbackText(value);
  } catch {
    return fallbackText(value);
  }
}

/** Cut `text` to at most `maxChars` UTF-16 units without splitting a surrogate pair. */
export function truncateText(text: string, maxChars: number): { text: string; truncated: boolean } {
  if (text.length <= maxChars) return { text, truncated: false };
  let end = Math.max(0, Math.floor(maxChars));
  const last = text.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return { text: text.slice(0, end), truncated: true };
}
