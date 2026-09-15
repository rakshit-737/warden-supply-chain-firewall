/**
 * Returns a normalised URL string when `value` is an absolute http(s) URL without embedded
 * credentials; otherwise null. Used for every externally supplied link (advisory references,
 * repository URLs) so `javascript:`, `data:` and similar schemes are never rendered as links.
 */
export function safeHttpUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 2048) return null;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
  if (parsed.username || parsed.password) return null;
  return parsed.href;
}

const CWE_RE = /^CWE-(\d{1,5})$/;
const ATTACK_RE = /^T(\d{4})(?:\.(\d{3}))?$/;

/** MITRE CWE page for a well-formed id such as "CWE-94"; null otherwise. */
export function cweUrl(id: string): string | null {
  const m = CWE_RE.exec(id.trim());
  return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : null;
}

/** MITRE ATT&CK page for a well-formed technique id such as "T1195" or "T1027.002"; null otherwise. */
export function attackTechniqueUrl(id: string): string | null {
  const m = ATTACK_RE.exec(id.trim());
  if (!m) return null;
  return m[2]
    ? `https://attack.mitre.org/techniques/T${m[1]}/${m[2]}/`
    : `https://attack.mitre.org/techniques/T${m[1]}/`;
}
