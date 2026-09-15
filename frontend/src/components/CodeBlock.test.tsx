import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CodeBlock } from "./CodeBlock";
import { SCRIPT_URL } from "../test/hostile";
import { ExternalLink } from "./ExternalLink";

describe("CodeBlock", () => {
  it("renders markup from attacker-controlled text as literal text", () => {
    const hostile = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    const { container } = render(<CodeBlock value={hostile} label="Evidence" />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("code")?.textContent).toBe(hostile);
    expect(screen.getByText("Evidence")).toBeInTheDocument();
  });

  it("makes bidirectional override characters visible", () => {
    const { container } = render(<CodeBlock value={"exec(‮evil)"} />);
    expect(container.querySelector("code")?.textContent).toBe("exec(<U+202E>evil)");
  });

  it("pretty-prints objects and says when it truncated", () => {
    const { container, rerender } = render(<CodeBlock value={{ path: "~/.ssh/id_rsa" }} />);
    expect(container.querySelector("code")?.textContent).toBe('{\n  "path": "~/.ssh/id_rsa"\n}');
    rerender(<CodeBlock value={"x".repeat(50)} maxChars={10} />);
    expect(container.querySelector("code")?.textContent).toBe("x".repeat(10));
    expect(screen.getByText("Showing the first 10 of 50 characters.")).toBeInTheDocument();
  });
});

describe("ExternalLink", () => {
  it("opens http(s) links in a new tab without opener or referrer", () => {
    render(<ExternalLink href="https://osv.dev/vulnerability/PYSEC-2026-1">OSV</ExternalLink>);
    const link = screen.getByRole("link", { name: /OSV/ });
    expect(link).toHaveAttribute("href", "https://osv.dev/vulnerability/PYSEC-2026-1");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it.each([SCRIPT_URL, "data:text/html,<script>alert(1)</script>", "https://user:pass@example.test/", "/relative/path"])(
    "renders %s as inert text",
    (href) => {
      render(<ExternalLink href={href} />);
      expect(screen.queryByRole("link")).toBeNull();
      expect(screen.getByText(href)).toBeInTheDocument();
    },
  );
});
