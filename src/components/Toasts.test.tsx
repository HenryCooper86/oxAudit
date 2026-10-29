import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { MAX_TOASTS, useToastStore } from "../lib/stores";
import { Toasts } from "./Toasts";

beforeEach(() => {
  vi.useFakeTimers();
  const { toasts, dismiss } = useToastStore.getState();
  for (const toast of toasts) dismiss(toast.id);
});

afterEach(() => {
  vi.useRealTimers();
});

const push = (kind: "info" | "success" | "error", message: string) =>
  act(() => useToastStore.getState().push(kind, message));

describe("toasts", () => {
  test("error toasts stay until dismissed", () => {
    render(<Toasts />);
    push("error", "Scan failed: disk full");
    act(() => vi.advanceTimersByTime(120_000));
    expect(screen.getByText("Scan failed: disk full")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Dismiss notification" }));
    expect(screen.queryByText("Scan failed: disk full")).not.toBeInTheDocument();
  });

  test("info toasts still dismiss on their own", () => {
    render(<Toasts />);
    push("success", "Settings saved");
    act(() => vi.advanceTimersByTime(5_100));
    expect(screen.queryByText("Settings saved")).not.toBeInTheDocument();
  });

  test("hovering a toast pauses its dismissal", () => {
    render(<Toasts />);
    push("info", "Scanning service-a…");
    act(() => vi.advanceTimersByTime(4_000));
    const toast = screen.getByText("Scanning service-a…").closest("[role=status]")!;
    fireEvent.mouseEnter(toast);
    act(() => vi.advanceTimersByTime(30_000));
    expect(screen.getByText("Scanning service-a…")).toBeInTheDocument();
    fireEvent.mouseLeave(toast);
    act(() => vi.advanceTimersByTime(500));
    expect(screen.getByText("Scanning service-a…")).toBeInTheDocument();
    act(() => vi.advanceTimersByTime(1_000));
    expect(screen.queryByText("Scanning service-a…")).not.toBeInTheDocument();
  });

  test("focus inside a toast pauses its dismissal", () => {
    render(<Toasts />);
    push("info", "Exported report");
    const dismissButton = screen.getByRole("button", { name: "Dismiss notification" });
    act(() => dismissButton.focus());
    act(() => vi.advanceTimersByTime(30_000));
    expect(screen.getByText("Exported report")).toBeInTheDocument();
    act(() => dismissButton.blur());
    act(() => vi.advanceTimersByTime(5_100));
    expect(screen.queryByText("Exported report")).not.toBeInTheDocument();
  });

  test("the stack is capped, dropping the oldest", () => {
    render(<Toasts />);
    for (let index = 1; index <= MAX_TOASTS + 2; index += 1) push("error", `problem ${index}`);
    expect(useToastStore.getState().toasts).toHaveLength(MAX_TOASTS);
    expect(screen.queryByText("problem 1")).not.toBeInTheDocument();
    expect(screen.queryByText("problem 2")).not.toBeInTheDocument();
    expect(screen.getByText(`problem ${MAX_TOASTS + 2}`)).toBeInTheDocument();
  });

  test("the stack fits narrow viewports", () => {
    render(<Toasts />);
    push("info", "hello");
    const stack = screen.getByText("hello").closest("[role=status]")!.parentElement!;
    expect(stack.className).not.toMatch(/(^|\s)w-96(\s|$)/);
    expect(stack.className).toMatch(/max-w-/);
  });
});
