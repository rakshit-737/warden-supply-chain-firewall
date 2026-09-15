/** File name built only from characters that are safe on every operating system. */
export function safeFileName(base: string, extension: string): string {
  const name =
    base
      .replace(/[^A-Za-z0-9._-]+/g, "_")
      .replace(/^[._]+/, "")
      .slice(0, 120) || "warden-export";
  const ext = extension.replace(/[^A-Za-z0-9]/g, "").slice(0, 10) || "txt";
  return `${name}.${ext}`;
}

/**
 * Save text as a file. The content is always handed to the browser as an opaque download and is
 * never rendered in the page, so an exported HTML report stays inert.
 */
export function downloadText(fileName: string, text: string): void {
  const blob = new Blob([text], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
