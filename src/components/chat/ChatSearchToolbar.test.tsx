import { createRef, useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, test, vi } from "vitest";

import { ChatSearchToolbar } from "./ChatSearchToolbar";

function setup(props: { query?: string; current?: number; total?: number } = {}) {
  const handlers = {
    onQueryChange: vi.fn(),
    onNext: vi.fn(),
    onPrevious: vi.fn(),
    onClose: vi.fn(),
  };
  const ref = createRef<HTMLInputElement>();
  const user = userEvent.setup();
  const view = render(
    <ChatSearchToolbar
      ref={ref}
      query={props.query ?? ""}
      current={props.current ?? 0}
      total={props.total ?? 0}
      {...handlers}
    />,
  );
  const input = screen.getByRole("searchbox", { name: "Search this conversation" });
  return { ...handlers, ref, user, input, ...view };
}

describe("ChatSearchToolbar", () => {
  test("is a labelled search landmark with a labelled input", () => {
    const { input } = setup();
    expect(screen.getByRole("search", { name: "Search conversation" })).toBeInTheDocument();
    expect(input).toHaveAttribute("type", "search");
  });

  test("shows 0 / 0 and disables match navigation when nothing matches", () => {
    setup({ query: "nothing", total: 0 });
    expect(screen.getByText("0 / 0")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous match" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next match" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Close conversation search" })).toBeEnabled();
  });

  test("shows the current match one-based and enables navigation", async () => {
    const { user, onNext, onPrevious } = setup({ query: "cve", current: 1, total: 5 });
    expect(screen.getByText("2 / 5")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Next match" }));
    expect(onNext).toHaveBeenCalledOnce();
    await user.click(screen.getByRole("button", { name: "Previous match" }));
    expect(onPrevious).toHaveBeenCalledOnce();
  });

  test("Enter goes to the next match and Shift+Enter to the previous", async () => {
    const { user, input, onNext, onPrevious } = setup({ query: "cve", total: 3 });
    await user.click(input);
    await user.keyboard("{Enter}");
    expect(onNext).toHaveBeenCalledOnce();
    expect(onPrevious).not.toHaveBeenCalled();

    await user.keyboard("{Shift>}{Enter}{/Shift}");
    expect(onPrevious).toHaveBeenCalledOnce();
    expect(onNext).toHaveBeenCalledOnce();
  });

  test("Escape in the input closes the search", async () => {
    const { user, input, onClose } = setup({ query: "cve", total: 3 });
    await user.click(input);
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledOnce();
  });

  test("the close button closes the search", async () => {
    const { user, onClose } = setup();
    await user.click(screen.getByRole("button", { name: "Close conversation search" }));
    expect(onClose).toHaveBeenCalledOnce();
  });

  test("reports each edit to the query", async () => {
    const onQueryChange = vi.fn();
    // Controlled, like the real caller, so each keystroke builds on the last.
    function Harness() {
      const [query, setQuery] = useState("");
      return (
        <ChatSearchToolbar
          query={query}
          current={0}
          total={0}
          onQueryChange={(next) => {
            onQueryChange(next);
            setQuery(next);
          }}
          onNext={vi.fn()}
          onPrevious={vi.fn()}
          onClose={vi.fn()}
        />
      );
    }
    const user = userEvent.setup();
    render(<Harness />);
    await user.type(screen.getByRole("searchbox"), "kev");
    expect(onQueryChange.mock.calls.map(([value]) => value)).toEqual(["k", "ke", "kev"]);
    expect(screen.getByRole("searchbox")).toHaveValue("kev");
  });

  test("forwards its ref to the input so callers can focus it", () => {
    const { ref, input } = setup();
    expect(ref.current).toBe(input);
    ref.current!.focus();
    expect(input).toHaveFocus();
  });
});
