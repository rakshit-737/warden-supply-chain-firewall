import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { AttackChain, Finding } from "../api/types";
import { AttackChainView } from "./AttackChainView";
import { SCRIPT_URL } from "../test/hostile";
import { FindingCard } from "./FindingCard";

// Test fixtures: hand-written finding and chain shapes, not real analysis output.
const FINDING: Finding = {
  code: "CREDENTIAL_ACCESS",
  severity: "high",
  weight: 6.5,
  message: "Reads ~/.aws/credentials at import time",
  evidence: { path: "~/.aws/credentials", snippet: '<script>alert("x")</script>' },
  finding_id: "0123456789abcdef",
  confidence: 0.9,
  category: "credential_access",
  title: "Reads cloud credentials",
  analyzer: "static_code",
  analyzer_version: "2.0.0",
  location: { file: "pkg/__init__.py", line: 12 },
  cwe: ["CWE-522"],
  attack: ["T1552.001"],
  remediation: "Remove the package and rotate the exposed credentials.",
  references: ["https://example.test/advisory", SCRIPT_URL],
};

const CHAIN: AttackChain = {
  id: "chain-1",
  title: "Install-time credential theft",
  severity: "critical",
  confidence: 0.92,
  steps: [
    {
      order: 2,
      technique_id: "T1041",
      technique_name: "Exfiltration Over C2 Channel",
      tactic: "exfiltration",
      finding_ids: ["f2"],
    },
    {
      order: 1,
      technique_id: "T1195.002",
      technique_name: "Compromise Software Supply Chain",
      tactic: "initial_access",
      finding_ids: ["f1"],
    },
    { order: 3, technique_id: SCRIPT_URL, technique_name: "Malformed id", tactic: null, finding_ids: [] },
  ],
};

describe("FindingCard", () => {
  it("shows classification, location, mappings and remediation", () => {
    render(<FindingCard finding={FINDING} />);
    expect(screen.getByRole("heading", { name: "Reads cloud credentials" })).toBeInTheDocument();
    expect(screen.getByText("Reads ~/.aws/credentials at import time")).toBeInTheDocument();
    expect(screen.getByText("CREDENTIAL_ACCESS")).toBeInTheDocument();
    expect(screen.getByText("Credential access")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("90%")).toBeInTheDocument();
    expect(screen.getByText("pkg/__init__.py:12")).toBeInTheDocument();

    const cwe = screen.getByRole("link", { name: /CWE-522/ });
    expect(cwe).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/522.html");
    expect(cwe).toHaveAttribute("rel", "noopener noreferrer");
    expect(cwe).toHaveAttribute("target", "_blank");
    expect(screen.getByRole("link", { name: /T1552.001/ })).toHaveAttribute(
      "href",
      "https://attack.mitre.org/techniques/T1552/001/",
    );
    expect(screen.getByText("Remove the package and rotate the exposed credentials.")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /javascript/ })).toBeNull();
    expect(screen.getByText(SCRIPT_URL)).toBeInTheDocument();
    expect(document.getElementById("finding-0123456789abcdef")).not.toBeNull();
  });

  it("reveals evidence on request, as inert text", async () => {
    const user = userEvent.setup();
    const { container } = render(<FindingCard finding={FINDING} />);
    const toggle = screen.getByRole("button", { name: "Show evidence" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText(/alert\(\\"x\\"\)/)).toBeNull();

    await user.click(toggle);
    expect(screen.getByRole("button", { name: "Hide evidence" })).toHaveAttribute("aria-expanded", "true");
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByText(/<script>alert/)).toBeInTheDocument();
  });

  it("renders a v1 signal without inventing Warden X details", () => {
    render(
      <FindingCard
        finding={{ code: "NETWORK_EGRESS", severity: "medium", weight: 3, message: "Opens network connections", evidence: {} }}
      />,
    );
    expect(screen.getByRole("heading", { name: "Opens network connections" })).toBeInTheDocument();
    expect(screen.queryByText("Location")).toBeNull();
    expect(screen.getByText("unknown")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show evidence" })).toBeNull();
  });
});

describe("AttackChainView", () => {
  it("orders steps by chain order and links techniques and findings", () => {
    render(<AttackChainView chains={[CHAIN]} findings={new Map([["f1", { code: "INSTALL_HOOK_EXEC" }]])} />);
    const steps = Array.from(screen.getByRole("list", { name: "Install-time credential theft steps" }).children);
    expect(steps).toHaveLength(3);
    expect(steps[0]).toHaveTextContent("Compromise Software Supply Chain");
    expect(steps[1]).toHaveTextContent("Exfiltration Over C2 Channel");
    expect(steps[2]).toHaveTextContent("Malformed id");

    const technique = screen.getByRole("link", { name: /T1195.002/ });
    expect(technique).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1195/002/");
    expect(technique).toHaveAttribute("rel", "noopener noreferrer");
    expect(screen.getByText("Initial access")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /javascript/ })).toBeNull();
    expect(screen.getByText(SCRIPT_URL)).toBeInTheDocument();

    expect(screen.getByRole("link", { name: "INSTALL_HOOK_EXEC" })).toHaveAttribute("href", "#finding-f1");
    expect(screen.getByRole("link", { name: "f2" })).toHaveAttribute("href", "#finding-f2");
  });

  it("hands a chosen finding to onFindingClick", async () => {
    const user = userEvent.setup();
    const onFindingClick = vi.fn();
    render(<AttackChainView chains={[CHAIN]} onFindingClick={onFindingClick} />);
    await user.click(screen.getByRole("link", { name: "f1" }));
    expect(onFindingClick).toHaveBeenCalledWith("f1");
  });

  it("copes with a chain that has no steps", () => {
    render(<AttackChainView chains={[{ title: "Partial chain", steps: [] }]} />);
    expect(screen.getByText("No steps were recorded for this chain.")).toBeInTheDocument();
  });
});
