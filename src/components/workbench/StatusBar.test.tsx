import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { version } from "../../../package.json";
import { useScanWorkStore } from "../../features/project-home/coordinator";
import { useAppStore } from "../../lib/stores";
import { StatusBar, StatusClock } from "./StatusBar";

beforeEach(() => {
  useAppStore.setState({ page: "dashboard", pageStatus: {}, aiReadiness: { status: "unsupported", version: 0 } });
  useScanWorkStore.setState({ active: null, recoveryError: null });
});

afterEach(() => {
  vi.useRealTimers();
});

test("the status bar keeps one live status region, AI readiness copy and no version", () => {
  render(<StatusBar />);
  const footer = document.querySelector("footer") as HTMLElement;
  expect(screen.getAllByRole("status")).toHaveLength(1);
  expect(screen.getByRole("status")).toHaveTextContent("neutral status:Ready");
  expect(footer).toHaveTextContent("AI not in this build");
  // The version moved to the sidebar footer, as in oxFuzz.
  expect(footer).not.toHaveTextContent(`v${version}`);
  expect(footer.querySelector("time")).not.toBeNull();
});

test("each readiness state keeps its status-bar wording", () => {
  const expected = {
    loading: "AI loading settings",
    checking: "AI checking",
    unconfigured: "AI not configured",
    offline: "AI offline",
    ready: "AI ready",
    unavailable: "AI status unavailable",
    unsupported: "AI not in this build",
  } as const;
  const view = render(<StatusBar />);
  for (const [status, label] of Object.entries(expected)) {
    act(() => useAppStore.setState({ aiReadiness: { status: status as keyof typeof expected, version: 0 } }));
    view.rerender(<StatusBar />);
    expect(document.querySelector("footer")).toHaveTextContent(label);
  }
});

test("a running scan shows its stage and path with a cancel action", () => {
  useScanWorkStore.setState({
    active: { stage: "Scanning source", path: "/work/repo", cancelling: false } as never,
  });
  render(<StatusBar />);
  expect(screen.getByRole("status")).toHaveTextContent("running status:Scanning source/work/repo");
  expect(screen.getByRole("button", { name: "Cancel active scan" })).toBeEnabled();
});

test("the clock shows the local time and ticks every second", () => {
  vi.useFakeTimers();
  let now = new Date(2026, 10, 18, 9, 30, 0);
  render(<StatusClock now={() => now} />);
  const clock = document.querySelector("time") as HTMLTimeElement;
  expect(clock).toHaveTextContent(now.toLocaleTimeString());
  expect(clock.dateTime).toBe(now.toISOString());
  now = new Date(2026, 10, 18, 9, 30, 1);
  act(() => vi.advanceTimersByTime(1000));
  expect(clock).toHaveTextContent(now.toLocaleTimeString());
});
