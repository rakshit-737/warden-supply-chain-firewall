import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { ConfirmDialog } from "./ConfirmDialog";
import { Tooltip } from "./Tooltip";

function DialogHarness({ onConfirm, busy = false }: { onConfirm: () => void; busy?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Activate
      </button>
      <ConfirmDialog
        open={open}
        title="Activate prod-strict?"
        description="It replaces the active production policy."
        confirmLabel="Activate policy"
        busy={busy}
        onConfirm={() => {
          onConfirm();
          setOpen(false);
        }}
        onCancel={() => setOpen(false)}
      />
    </>
  );
}

describe("ConfirmDialog", () => {
  it("focuses Cancel, traps Tab inside and restores focus on Escape", async () => {
    const user = userEvent.setup();
    render(<DialogHarness onConfirm={vi.fn()} />);
    const trigger = screen.getByRole("button", { name: "Activate" });
    await user.click(trigger);

    const dialog = screen.getByRole("alertdialog", { name: "Activate prod-strict?" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAccessibleDescription("It replaces the active production policy.");
    const cancel = screen.getByRole("button", { name: "Cancel" });
    const confirm = screen.getByRole("button", { name: "Activate policy" });
    expect(cancel).toHaveFocus();

    await user.tab();
    expect(confirm).toHaveFocus();
    await user.tab();
    expect(cancel).toHaveFocus();
    await user.tab({ shift: true });
    expect(confirm).toHaveFocus();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(trigger).toHaveFocus();
  });

  it("confirms, and ignores confirmation while busy", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    const { unmount } = render(<DialogHarness onConfirm={onConfirm} />);
    await user.click(screen.getByRole("button", { name: "Activate" }));
    await user.click(screen.getByRole("button", { name: "Activate policy" }));
    expect(onConfirm).toHaveBeenCalledOnce();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    unmount();

    const busyConfirm = vi.fn();
    render(<DialogHarness onConfirm={busyConfirm} busy />);
    await user.click(screen.getByRole("button", { name: "Activate" }));
    await user.click(screen.getByRole("button", { name: "Working" }));
    await user.keyboard("{Escape}");
    expect(busyConfirm).not.toHaveBeenCalled();
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });
});

describe("Tooltip", () => {
  it("describes its trigger on focus and hides on Escape", async () => {
    const user = userEvent.setup();
    render(
      <Tooltip content="Likelihood the finding is a true positive">
        {(trigger) => (
          <button type="button" {...trigger}>
            Confidence
          </button>
        )}
      </Tooltip>,
    );
    expect(screen.queryByRole("tooltip")).toBeNull();
    await user.tab();
    expect(screen.getByRole("tooltip")).toHaveTextContent("Likelihood the finding is a true positive");
    expect(screen.getByRole("button", { name: "Confidence" })).toHaveAccessibleDescription(
      "Likelihood the finding is a true positive",
    );
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("shows on hover and hides when the pointer leaves", async () => {
    const user = userEvent.setup();
    render(<Tooltip content="Help text">{(trigger) => <button type="button" {...trigger}>Info</button>}</Tooltip>);
    await user.hover(screen.getByRole("button", { name: "Info" }));
    expect(screen.getByRole("tooltip")).toBeInTheDocument();
    await user.unhover(screen.getByRole("button", { name: "Info" }));
    expect(screen.queryByRole("tooltip")).toBeNull();
  });
});
