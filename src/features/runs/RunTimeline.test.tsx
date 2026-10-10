import { act, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { RunTimeline } from "./RunTimeline";
import { reconcileBackendWork, useScanWorkStore } from "../project-home/coordinator";

const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("../../lib/events", () => ({ listen: async (name: string, handler: (event: { payload: unknown }) => void) => { listeners.set(name, handler); return () => listeners.delete(name); } }));

beforeEach(() => {
  listeners.clear();
  useScanWorkStore.setState({ active: null, check: null, backend: { active: null, recent: [] }, lastTargets: {}, recoveryError: null });
  reconcileBackendWork({ active: { operationId: "current", kind: "source", target: "/repo", status: "running", startedAtMs: 1, updatedAtMs: 2 }, recent: [] });
});

const event = (operationId: string, sequence: number, state: string, runId = "run_current") => ({ schemaVersion: 1, operationId, runId, sequence, occurredAtMs: sequence, event: { kind: "stage_changed", state } });

test.each([null, ["detecting"], { toString: "detecting" }, 42])("malformed lifecycle state %j is ignored without coercion or advancing the sequence", async (state) => {
  render(<RunTimeline kind="source" running hasCompletedResult={false} />);
  await waitFor(() => expect(listeners.has("run://event")).toBe(true));
  await act(async () => {
    expect(() => listeners.get("run://event")?.({ payload: { ...event("current", 100, "detecting"), event: { kind: "stage_changed", state } } })).not.toThrow();
  });
  expect(screen.queryByText("Detecting findings")).not.toBeInTheDocument();
  await act(async () => listeners.get("run://event")?.({ payload: event("current", 1, "detecting") }));
  expect(screen.getByRole("status")).toHaveTextContent("Detecting findings");
});

test("unknown live progress shows no invented stages, count or overall percentage", () => {
  render(<RunTimeline kind="source" running hasCompletedResult={false} />);
  const region = screen.getByRole("region", { name: "Scan progress" });
  expect(within(region).getByText(/waiting for.*progress/i)).toBeInTheDocument();
  expect(within(region).queryByRole("list")).not.toBeInTheDocument();
  expect(within(region).queryByRole("progressbar")).not.toBeInTheDocument();
  expect(region).not.toHaveTextContent(/%|ETA/);
});

test("only actual stages for the owned operation appear and stale sequence events cannot move the stage back", async () => {
  render(<RunTimeline kind="source" running hasCompletedResult />);
  await waitFor(() => expect(listeners.has("run://event")).toBe(true));
  await act(async () => listeners.get("run://event")?.({ payload: event("old", 1, "persisting") }));
  expect(screen.queryByText("Saving evidence")).not.toBeInTheDocument();
  await act(async () => listeners.get("run://event")?.({ payload: event("current", 2, "detecting") }));
  expect(screen.getByRole("status")).toHaveTextContent("Detecting findings");
  expect(screen.queryByText("Discovering targets")).not.toBeInTheDocument();
  await act(async () => listeners.get("run://event")?.({ payload: event("current", 3, "enriching") }));
  await act(async () => listeners.get("run://event")?.({ payload: event("current", 2, "discovering") }));
  const stages = screen.getByRole("list", { name: "Reported scan stages" });
  expect(within(stages).getAllByRole("listitem")).toHaveLength(2);
  expect(within(stages).getByText("Enriching evidence").closest("li")).toHaveAttribute("aria-current", "step");
  expect(screen.queryByText("Discovering targets")).not.toBeInTheDocument();
  expect(screen.getByText(/previous.*result remains/i)).toBeInTheDocument();
});

test("known phase counts are labelled without percent and invalid totals remain unknown", () => {
  const view = render(<RunTimeline kind="source" running hasCompletedResult={false} progress={{ phase: "scanning", done: 25, total: 80, unit: "files", label: "Scanning files" }} />);
  expect(screen.getByText("25 of 80 files")).toBeInTheDocument();
  expect(screen.getByRole("region", { name: "Scan progress" })).not.toHaveTextContent("%");
  view.rerender(<RunTimeline kind="source" running hasCompletedResult={false} progress={{ phase: "scanning", done: 25, total: 0, unit: "files", label: "Scanning files" }} />);
  expect(screen.queryByText(/25 of/)).not.toBeInTheDocument();
});

test("replacing the active operation drops the prior stages and idle receipts do not imply a new scan completed", async () => {
  const view = render(<RunTimeline kind="source" running hasCompletedResult />);
  await waitFor(() => expect(listeners.has("run://event")).toBe(true));
  await act(async () => listeners.get("run://event")?.({ payload: event("current", 1, "detecting") }));
  await act(async () => reconcileBackendWork({ active: { operationId: "replacement", kind: "source", target: "/other", status: "running", startedAtMs: 2, updatedAtMs: 3 }, recent: [] }));
  expect(screen.queryByText("Detecting findings")).not.toBeInTheDocument();
  expect(screen.getByText(/waiting for.*progress/i)).toBeInTheDocument();
  view.rerender(<RunTimeline kind="source" running={false} hasCompletedResult />);
  expect(screen.queryByRole("region", { name: "Scan progress" })).not.toBeInTheDocument();
});

test("advancing beyond the native count phase cannot display that count as current progress", async () => {
  render(<RunTimeline kind="source" running hasCompletedResult={false} progress={{ phase: "scanning", label: "Scanning files", done: 80, total: 80, unit: "files" }} />);
  await waitFor(() => expect(listeners.has("run://event")).toBe(true));
  await act(async () => listeners.get("run://event")?.({ payload: event("current", 4, "enriching") }));
  expect(screen.getByRole("status")).toHaveTextContent("Enriching evidence");
  expect(screen.queryByText("80 of 80 files")).not.toBeInTheDocument();
});

test("a terminal operation cannot be reopened by a later stage event", async () => {
  render(<RunTimeline kind="source" running hasCompletedResult={false} />);
  await waitFor(() => expect(listeners.has("run://event")).toBe(true));
  await act(async () => listeners.get("run://event")?.({ payload: { ...event("current", 10, "completed"), event: { kind: "run_terminal", state: "completed" } } }));
  await act(async () => listeners.get("run://event")?.({ payload: event("current", 11, "detecting") }));
  expect(screen.getByRole("status")).toHaveTextContent("Operation completed");
});

test("phase counts and details from a replaced operation are hidden", () => {
  render(<RunTimeline kind="source" running hasCompletedResult={false}
    progress={{ operationId: "old", phase: "scanning", label: "Scanning files", done: 25, total: 80, unit: "files" }}
    detail="old activity" logs={["old log"]} detailsOperationId="old" />);
  expect(screen.queryByText("25 of 80 files")).not.toBeInTheDocument();
  expect(screen.queryByText("old activity")).not.toBeInTheDocument();
  expect(screen.queryByText("old log")).not.toBeInTheDocument();
});
