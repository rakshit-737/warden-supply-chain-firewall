import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DataTable, type Column } from "./DataTable";

interface Row {
  id: string;
  name: string;
  score: number | null;
}

const ROWS: Row[] = [
  { id: "1", name: "bravo", score: 2 },
  { id: "2", name: "alpha", score: 10 },
  { id: "3", name: "charlie", score: null },
];

const COLUMNS: Column<Row>[] = [
  { id: "name", header: "Name", cell: (row) => row.name, sortValue: (row) => row.name },
  {
    id: "score",
    header: "Score",
    align: "right",
    cell: (row) => (row.score === null ? "none" : String(row.score)),
    sortValue: (row) => row.score,
  },
];

function names(): (string | null | undefined)[] {
  return screen
    .getAllByRole("row")
    .slice(1)
    .map((row) => within(row).getAllByRole("cell")[0]?.textContent);
}

describe("DataTable", () => {
  it("sorts rows by a column, keeping blank values last", async () => {
    const user = userEvent.setup();
    render(<DataTable caption="Packages" columns={COLUMNS} rows={ROWS} rowKey={(row) => row.id} />);
    expect(screen.getByRole("table", { name: "Packages" })).toBeInTheDocument();
    const header = screen.getByRole("columnheader", { name: /Score/ });
    expect(header).toHaveAttribute("aria-sort", "none");

    await user.click(within(header).getByRole("button"));
    expect(header).toHaveAttribute("aria-sort", "ascending");
    expect(names()).toEqual(["bravo", "alpha", "charlie"]);

    await user.click(within(header).getByRole("button"));
    expect(header).toHaveAttribute("aria-sort", "descending");
    expect(names()).toEqual(["alpha", "bravo", "charlie"]);

    await user.click(within(screen.getByRole("columnheader", { name: /Name/ })).getByRole("button"));
    expect(names()).toEqual(["alpha", "bravo", "charlie"]);
    expect(header).toHaveAttribute("aria-sort", "none");
  });

  it("reports sort changes without reordering rows when sorting is controlled", async () => {
    const user = userEvent.setup();
    const onSortChange = vi.fn();
    render(
      <DataTable
        caption="Packages"
        columns={COLUMNS}
        rows={ROWS}
        rowKey={(row) => row.id}
        sort={{ columnId: "name", direction: "asc" }}
        onSortChange={onSortChange}
      />,
    );
    expect(names()).toEqual(["bravo", "alpha", "charlie"]);
    await user.click(within(screen.getByRole("columnheader", { name: /Name/ })).getByRole("button"));
    expect(onSortChange).toHaveBeenCalledWith({ columnId: "name", direction: "desc" });
  });

  it("drives server pagination through offsets", async () => {
    const user = userEvent.setup();
    const onOffsetChange = vi.fn();
    render(
      <DataTable
        caption="Scans"
        columns={COLUMNS}
        rows={ROWS}
        rowKey={(row) => row.id}
        pagination={{ total: 60, limit: 25, offset: 25, onOffsetChange }}
      />,
    );
    expect(screen.getByText("26–50 of 60")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(onOffsetChange).toHaveBeenLastCalledWith(50);
    await user.click(screen.getByRole("button", { name: "Previous" }));
    expect(onOffsetChange).toHaveBeenLastCalledWith(0);
  });

  it("disables paging past either end", () => {
    render(
      <DataTable
        caption="Scans"
        columns={COLUMNS}
        rows={ROWS}
        rowKey={(row) => row.id}
        pagination={{ total: 3, limit: 25, offset: 0, onOffsetChange: vi.fn() }}
      />,
    );
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });

  it("shows loading, empty and error states", async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();
    const { rerender } = render(
      <DataTable caption="Scans" columns={COLUMNS} rows={undefined} rowKey={(row) => row.id} loading />,
    );
    expect(screen.getByRole("status")).toHaveTextContent("Loading scans");

    rerender(<DataTable caption="Scans" columns={COLUMNS} rows={[]} rowKey={(row) => row.id} empty={<p>No scans yet.</p>} />);
    expect(screen.getByText("No scans yet.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();

    rerender(
      <DataTable
        caption="Scans"
        columns={COLUMNS}
        rows={undefined}
        rowKey={(row) => row.id}
        error={{ status: 500, code: null, message: "The server failed.", requestId: "req-9" }}
        onRetry={onRetry}
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("The server failed.");
    expect(screen.getByRole("alert")).toHaveTextContent("req-9");
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it("keeps rows visible and marks the table busy while refetching", () => {
    render(<DataTable caption="Scans" columns={COLUMNS} rows={ROWS} rowKey={(row) => row.id} loading />);
    expect(screen.getByRole("table")).toHaveAttribute("aria-busy", "true");
    expect(names()).toHaveLength(3);
  });
});
