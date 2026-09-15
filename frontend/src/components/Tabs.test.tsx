import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Tabs, type TabItem } from "./Tabs";

const TABS: TabItem[] = [
  { id: "findings", label: "Findings", count: 3, content: <p>Finding list</p> },
  { id: "risk", label: "Risk", content: <p>Risk bars</p> },
  { id: "provenance", label: "Provenance", content: <p>Provenance data</p> },
];

describe("Tabs", () => {
  it("moves selection and focus with arrow keys, Home and End", async () => {
    const user = userEvent.setup();
    render(<Tabs label="Scan details" tabs={TABS} />);
    const findings = screen.getByRole("tab", { name: /Findings/ });
    expect(findings).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel")).toHaveTextContent("Finding list");

    findings.focus();
    await user.keyboard("{ArrowRight}");
    const risk = screen.getByRole("tab", { name: "Risk" });
    expect(risk).toHaveFocus();
    expect(risk).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel", { name: "Risk" })).toHaveTextContent("Risk bars");

    await user.keyboard("{End}");
    expect(screen.getByRole("tab", { name: "Provenance" })).toHaveFocus();
    await user.keyboard("{ArrowRight}");
    expect(findings).toHaveFocus();
    await user.keyboard("{ArrowLeft}");
    expect(screen.getByRole("tab", { name: "Provenance" })).toHaveFocus();
    await user.keyboard("{Home}");
    expect(findings).toHaveFocus();
  });

  it("keeps only the selected tab in the Tab order and reports changes", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Tabs label="Scan details" tabs={TABS} value="risk" onChange={onChange} />);
    expect(screen.getByRole("tab", { name: "Risk" })).toHaveAttribute("tabindex", "0");
    expect(screen.getByRole("tab", { name: /Findings/ })).toHaveAttribute("tabindex", "-1");
    await user.click(screen.getByRole("tab", { name: "Provenance" }));
    expect(onChange).toHaveBeenCalledWith("provenance");
  });
});
