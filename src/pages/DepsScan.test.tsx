import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { DepsScanPage } from "./DepsScan";
import { api } from "../lib/api";
import { useAppStore } from "../lib/stores";
import { reconcileBackendWork, useScanWorkStore } from "../features/project-home/coordinator";

const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("../lib/events", () => ({ listen: async (name: string, handler: (event: { payload: unknown }) => void) => { listeners.set(name, handler); return () => listeners.delete(name); } }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

beforeEach(() => {
  vi.clearAllMocks(); listeners.clear();
  useAppStore.setState({ activeProject: "/repo", selectedProject: null, pageStatus: {} });
  useScanWorkStore.setState({ active: null, check: null, backend: { active: null, recent: [] }, lastTargets: {}, recoveryError: null });
  vi.spyOn(api, "setActiveProject").mockResolvedValue();
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([]);
  vi.spyOn(api, "scanWorkStatus").mockResolvedValue({ active: null, recent: [] });
});

test("recovered dependency progress keeps exact ownership and reports lockfile counts without synthetic provider units", async () => {
  reconcileBackendWork({ active: { operationId: "current-deps", kind: "dependencies", target: "/repo", status: "running", startedAtMs: 1, updatedAtMs: 2 }, recent: [] });
  render(<DepsScanPage />);
  await waitFor(() => expect(listeners.has("deps://progress")).toBe(true));
  await act(async () => listeners.get("deps://progress")?.({ payload: { operationId: "old", phase: "parsing", done: 8, total: 9 } }));
  expect(screen.queryByText("8 of 9 lockfiles")).not.toBeInTheDocument();
  await act(async () => listeners.get("deps://progress")?.({ payload: { operationId: "current-deps", phase: "parsing", done: 1, total: 3 } }));
  const progress = screen.getByRole("region", { name: "Scan progress" });
  expect(within(progress).getByText("1 of 3 lockfiles")).toBeInTheDocument();
  await act(async () => listeners.get("deps://progress")?.({ payload: { operationId: "current-deps", phase: "querying-osv", done: 0, total: 1 } }));
  expect(progress).toHaveTextContent("Querying OSV advisories");
  expect(progress).not.toHaveTextContent(/of 1|%/);
});

test("typing a dependency target and pressing Enter never starts the scan or lockfile discovery", async () => {
  const scan = vi.spyOn(api, "scanDependencies");
  const find = vi.spyOn(api, "findLockfiles");
  render(<DepsScanPage />);
  await act(async () => {
    fireEvent.change(screen.getByRole("textbox", { name: "Project folder path" }), { target: { value: "/candidate" } });
    fireEvent.keyDown(screen.getByRole("textbox", { name: "Project folder path" }), { key: "Enter" });
  });
  expect(scan).not.toHaveBeenCalled();
  expect(find).not.toHaveBeenCalled();
});

test('malformed owned native progress cannot replace the current phase or crash the page', async () => {
  reconcileBackendWork({ active: { operationId: 'current-deps', kind: 'dependencies', target: '/repo', status: 'running', startedAtMs: 1, updatedAtMs: 2 }, recent: [] });
  render(<DepsScanPage />);
  await waitFor(() => expect(listeners.has('deps://progress')).toBe(true));
  await act(async () => listeners.get('deps://progress')?.({ payload: { operationId: 'current-deps', phase: 'parsing', done: 1, total: 3 } }));
  for (const payload of [null, { operationId: 'current-deps', phase: { invalid: true } }, { operationId: 'current-deps', phase: 'invented', done: 100, total: 100 }]) {
    await act(async () => listeners.get('deps://progress')?.({ payload }));
  }
  const progress = screen.getByRole('region', { name: 'Scan progress' });
  expect(progress).toHaveTextContent('1 of 3 lockfiles');
  expect(progress).not.toHaveTextContent('invented');
});
