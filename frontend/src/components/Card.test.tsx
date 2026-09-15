import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Card } from "./Card";

describe("Card", () => {
  it("is a region named by its title, with actions in the header", () => {
    render(
      <Card title="Recent scans" description="Newest first" actions={<button type="button">Refresh</button>}>
        <p>Rows</p>
      </Card>,
    );
    const region = screen.getByRole("region", { name: "Recent scans" });
    expect(region).toHaveTextContent("Rows");
    expect(region).toHaveTextContent("Newest first");
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });

  it("is not a landmark without a title", () => {
    render(
      <Card>
        <p>Plain panel</p>
      </Card>,
    );
    expect(screen.queryByRole("region")).toBeNull();
    expect(screen.getByText("Plain panel")).toBeInTheDocument();
  });
});
