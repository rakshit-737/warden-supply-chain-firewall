import { describe, expect, it } from "vitest";
import { revealInvisible, toDisplayText, truncateText } from "./text";

describe("revealInvisible", () => {
  it("marks bidirectional overrides, zero-width, control and tag characters", () => {
    expect(revealInvisible("admin‮gnp.exe")).toBe("admin<U+202E>gnp.exe");
    expect(revealInvisible("pass​word")).toBe("pass<U+200B>word");
    expect(revealInvisible("[31mred")).toBe("<U+001B>[31mred");
    expect(revealInvisible("hidden\u{E0041}tag")).toBe("hidden<U+E0041>tag");
  });

  it("keeps ordinary text, whitespace and astral characters intact", () => {
    const text = "line one\n\tline two é \u{1F4E6}";
    expect(revealInvisible(text)).toBe(text);
  });
});

describe("truncateText", () => {
  it("never splits a surrogate pair", () => {
    expect(truncateText("ab\u{1F600}cd", 3)).toEqual({ text: "ab", truncated: true });
    expect(truncateText("abc", 3)).toEqual({ text: "abc", truncated: false });
  });
});

describe("toDisplayText", () => {
  it("pretty-prints objects and never throws", () => {
    expect(toDisplayText({ a: 1 })).toBe('{\n  "a": 1\n}');
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => toDisplayText(circular)).not.toThrow();
    expect(toDisplayText(10n)).toBe("10");
    expect(toDisplayText(undefined)).toBe("");
  });
});
