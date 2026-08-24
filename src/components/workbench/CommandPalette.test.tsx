import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { CommandPalette } from "./CommandPalette";
import { useAppStore } from "../../lib/stores";

/**
 * The palette exists so an analyst can move between screens without reaching
 * for the mouse. The failure that matters is not "it looks wrong" — it is
 * typing three characters, pressing Enter, and landing somewhere else.
 */
describe("CommandPalette", () => {
  beforeEach(() => {
    useAppStore.setState({ page: "dashboard" });
  });

  function setup(open = true) {
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(<CommandPalette open={open} onClose={onClose} />);
    return { onClose, user };
  }

  const page = () => useAppStore.getState().page;

  test("renders nothing while closed", () => {
    setup(false);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  test("opens focused on the input so typing goes straight to the filter", async () => {
    setup();
    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: /search commands/i })).toHaveFocus(),
    );
  });

  test("lists every screen before anything is typed", () => {
    setup();
    expect(screen.getAllByRole("option").length).toBeGreaterThanOrEqual(15);
  });

  test("narrows the list as the query is typed", async () => {
    const { user } = setup();
    const before = screen.getAllByRole("option").length;
    await user.type(screen.getByRole("textbox", { name: /search commands/i }), "export");
    const after = screen.getAllByRole("option");
    expect(after.length).toBeLessThan(before);
    expect(after[0]).toHaveTextContent("Export Center");
  });

  test("Enter navigates to the highlighted command", async () => {
    const { user, onClose } = setup();
    await user.type(screen.getByRole("textbox", { name: /search commands/i }), "quality");
    await user.keyboard("{Enter}");

    expect(page()).toBe("quality-lab");
    expect(onClose).toHaveBeenCalledOnce();
  });

  test("arrow keys move the highlight before Enter commits", async () => {
    const { user } = setup();
    await user.type(screen.getByRole("textbox", { name: /search commands/i }), "scan");

    const options = screen.getAllByRole("option");
    expect(options.length).toBeGreaterThan(1);
    const first = options[0].textContent;
    const second = options[1].textContent;
    expect(first).not.toEqual(second);

    await user.keyboard("{ArrowDown}");
    expect(screen.getAllByRole("option")[1]).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{Enter}");

    // Enter acts on the highlight, not on the first match.
    const { PAGE_META } = await import("../../lib/workbench");
    expect(PAGE_META[page()].title).toBe(second);
  });

  test("wrapping past the top reaches the last command", async () => {
    const { user } = setup();
    await user.type(screen.getByRole("textbox", { name: /search commands/i }), "scan");
    const options = screen.getAllByRole("option");

    await user.keyboard("{ArrowUp}");
    // A single Up from the top should reach the end, as every other palette
    // behaves — not sit at zero.
    expect(screen.getAllByRole("option")[options.length - 1]).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });

  test("Enter with no matches does nothing rather than guessing", async () => {
    const { user, onClose } = setup();
    await user.type(screen.getByRole("textbox", { name: /search commands/i }), "qqqzzz");
    expect(screen.queryAllByRole("option")).toHaveLength(0);

    await user.keyboard("{Enter}");
    // Falling back to "the first thing in the full list" is how a palette
    // navigates somewhere the user never asked for.
    expect(page()).toBe("dashboard");
    expect(onClose).not.toHaveBeenCalled();
  });

  test("says so when nothing matches", async () => {
    const { user } = setup();
    await user.type(screen.getByRole("textbox", { name: /search commands/i }), "qqqzzz");
    expect(screen.getByRole("status")).toHaveTextContent(/nothing matches/i);
  });

  test("Escape closes without navigating", async () => {
    const { user, onClose } = setup();
    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: /search commands/i })).toHaveFocus(),
    );
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledOnce();
    expect(page()).toBe("dashboard");
  });

  test("clicking the backdrop closes without navigating", async () => {
    const { user, onClose } = setup();
    // The overlay is the dialog's parent; clicking the dialog itself must not
    // dismiss it.
    const dialog = screen.getByRole("dialog");
    await user.click(dialog);
    expect(onClose).not.toHaveBeenCalled();

    await user.click(dialog.parentElement as HTMLElement);
    expect(onClose).toHaveBeenCalledOnce();
    expect(page()).toBe("dashboard");
  });

  test("clicking a command navigates to it", async () => {
    const { user, onClose } = setup();
    await user.type(screen.getByRole("textbox", { name: /search commands/i }), "settings");
    await user.click(screen.getAllByRole("option")[0]);
    expect(page()).toBe("settings");
    expect(onClose).toHaveBeenCalledOnce();
  });

  test("the highlight resets when the query changes", async () => {
    const { user } = setup();
    const input = screen.getByRole("textbox", { name: /search commands/i });
    await user.type(input, "scan");
    await user.keyboard("{ArrowDown}");
    expect(screen.getAllByRole("option")[1]).toHaveAttribute("aria-selected", "true");

    await user.clear(input);
    await user.type(input, "export");

    // Keeping the old index would leave the highlight on whatever happens to
    // occupy that position in the new list.
    expect(screen.getAllByRole("option")[0]).toHaveAttribute("aria-selected", "true");
  });

  test("is announced as a labelled modal dialog", () => {
    setup();
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAccessibleName("Command palette");
    // The listbox and active option are what a screen reader follows as the
    // highlight moves.
    expect(screen.getByRole("listbox")).toBeInTheDocument();
  });
});
