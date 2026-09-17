/// <reference types="node" />
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { palette } from "./palette";

// Tailwind 4 reads colours from the @theme block in index.css; charts read palette.ts.
// Both must carry the same values. (Vitest stubs CSS imports, so the file is read directly.)
const css = readFileSync(resolve(process.cwd(), "src/index.css"), "utf8");

function themeColor(name: string): string | undefined {
  const match = new RegExp(`--color-${name}:\\s*(#[0-9a-fA-F]{6});`).exec(css);
  return match?.[1]?.toUpperCase();
}

describe("palette", () => {
  const expected: Record<string, string> = {
    page: palette.page,
    panel: palette.panel,
    raised: palette.raised,
    sunken: palette.sunken,
    line: palette.line,
    "line-strong": palette.lineStrong,
    ink: palette.ink,
    "ink-secondary": palette.inkSecondary,
    "ink-muted": palette.inkMuted,
    accent: palette.accent,
    ...Object.fromEntries(Object.entries(palette.severity).map(([k, v]) => [`sev-${k}`, v])),
    ...Object.fromEntries(Object.entries(palette.decision).map(([k, v]) => [`verdict-${k}`, v])),
  };

  it.each(Object.entries(expected))("index.css --color-%s matches palette.ts", (name, value) => {
    expect(themeColor(name)).toBe(value.toUpperCase());
  });
});
