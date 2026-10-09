import { act, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import * as coordinator from "./coordinator";
import type { ScanWorkDescriptor } from "../../lib/types";
import { StatusBar } from "../../components/workbench/StatusBar";

const backend = vi.hoisted(() => ({
  cancelScan: vi.fn(), cancelDependencyScan: vi.fn(), cancelScanWork: vi.fn(), scanWorkStatus: vi.fn(),
}));
vi.mock("../../lib/api", () => ({ api: backend }));
const handlers = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
const subscription = vi.hoisted(() => ({ ready: null as Promise<void> | null, failure: null as Error | null }));
vi.mock("../../lib/events", () => ({ listen: async (event: string, callback: (event: { payload: unknown }) => void) => {
  if (subscription.failure) throw subscription.failure;
  if (subscription.ready) await subscription.ready;
  handlers.set(event, callback);
  return () => handlers.delete(event);
} }));

const work = (operationId = "remote-operation", status: ScanWorkDescriptor["status"] = "running"): ScanWorkDescriptor => ({
  operationId, kind: "image" as const, target: "registry.local/app:1", status,
  runId: null, startedAtMs: 10, updatedAtMs: 20,
});
beforeEach(() => {
  vi.clearAllMocks();
  handlers.clear();
  subscription.ready = null;
  subscription.failure = null;
  coordinator.useScanWorkStore.setState({ active: null, check: null, backend: { active: null, recent: [] }, recoveryError: null, lastTargets: {} });
  backend.cancelScanWork.mockResolvedValue(true);
  backend.scanWorkStatus.mockResolvedValue({ active: null, recent: [] });
});

test("initial status is read only after recovery subscriptions are registered", async () => {
  let ready!: () => void;
  subscription.ready = new Promise(resolve => { ready = resolve; });
  render(<RecoveryHarness />);
  expect(backend.scanWorkStatus).not.toHaveBeenCalled();
  await act(async () => ready());
  await waitFor(() => expect(backend.scanWorkStatus).toHaveBeenCalledTimes(1));
  expect(handlers.has("work://changed")).toBe(true);
});

test("a failed event subscription remains visible and polling still recovers other-client work", async () => {
  vi.useFakeTimers();
  try {
    subscription.failure = new Error("event bridge disconnected");
    render(<><RecoveryHarness /><StatusBar /></>);
    await act(async () => {});
    expect(screen.getByText("Scan status unavailable")).toBeInTheDocument();
    backend.scanWorkStatus.mockResolvedValue({ active: work("polled-operation"), recent: [] });
    await act(async () => vi.advanceTimersByTimeAsync(2_000));
    expect(coordinator.useScanWorkStore.getState().active?.operationId).toBe("polled-operation");
    expect(screen.getByText("Scan status unavailable")).toBeInTheDocument();
  } finally { vi.useRealTimers(); }
});

test("malformed backend work cannot replace ownership or throw from an event callback", async () => {
  backend.scanWorkStatus.mockResolvedValue({ active: work(), recent: [] });
  render(<><RecoveryHarness /><StatusBar /></>);
  await screen.findByText("image:registry.local/app:1");
  await act(async () => handlers.get("work://changed")?.({ payload: { active: { ...work("bad"), kind: "future-engine", status: "unknown" }, recent: [] } }));
  expect(coordinator.useScanWorkStore.getState().active?.operationId).toBe("remote-operation");
  expect(coordinator.useScanWorkStore.getState().recoveryError).toMatch(/invalid|unavailable/i);
  expect(screen.getByText("Scan status unavailable")).toBeInTheDocument();
});

test("local ownership generates a UUID to bind exact backend work and cancellation", async () => {
  const ownership = coordinator.acquireScan("source", "/repo", "Scanning source")!;
  const active = coordinator.useScanWorkStore.getState().active!;
  expect(active.operationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  await coordinator.cancelActiveScan();
  expect(backend.cancelScanWork).toHaveBeenCalledWith(active.operationId);
  expect(coordinator.useScanWorkStore.getState().active).toMatchObject({ id: ownership, cancelling: true });
  expect(backend.cancelScan).not.toHaveBeenCalled();
});

test("backend snapshots recover external ownership and terminal snapshots release it", () => {
  coordinator.reconcileBackendWork?.({ active: work(), recent: [] });
  expect(coordinator.useScanWorkStore.getState().active).toMatchObject({ owner: "image", operationId: "remote-operation", path: "registry.local/app:1", recovered: true });
  expect(coordinator.acquireScan("dependencies", "/other", "Checking dependencies")).toBeNull();
  coordinator.reconcileBackendWork?.({ active: null, recent: [{ ...work(), status: "completed", runId: "saved-image" }] });
  expect(coordinator.useScanWorkStore.getState().active).toBeNull();
  expect(coordinator.useScanWorkStore.getState().backend.recent[0].runId).toBe("saved-image");
});

test("a terminal event cannot retire local ownership before its HTTP result settles", () => {
  const ownership = coordinator.acquireScan("source", "/repo", "Scanning source")!;
  const operationId = coordinator.useScanWorkStore.getState().active!.operationId;
  coordinator.reconcileBackendWork?.({ active: { ...work(operationId), kind: "source", target: "/repo" }, recent: [] });
  coordinator.reconcileBackendWork?.({ active: null, recent: [{ ...work(operationId), kind: "source", target: "/repo", status: "completed", runId: "saved-source" }] });
  expect(coordinator.useScanWorkStore.getState().active).toMatchObject({ id: ownership, terminalStatus: "completed" });
  coordinator.releaseScan(ownership);
  expect(coordinator.useScanWorkStore.getState().active).toBeNull();
});

test("a rejected old cancellation cannot mark replacement work as uncancelled", async () => {
  let reject!: (error: Error) => void;
  backend.cancelScanWork.mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }));
  const ownership = coordinator.acquireScan("source", "/old", "Scanning source")!;
  const oldId = coordinator.useScanWorkStore.getState().active!.operationId;
  const pending = coordinator.cancelActiveScan();
  expect(backend.cancelScanWork).toHaveBeenCalledWith(oldId);
  coordinator.releaseScan(ownership);
  const replacement = coordinator.acquireScan("dependencies", "/new", "Checking dependencies")!;
  await coordinator.cancelActiveScan();
  reject(new Error("old connection failed"));
  await pending;
  expect(coordinator.useScanWorkStore.getState().active).toMatchObject({ id: replacement, cancelling: true });
});

function RecoveryHarness() {
  coordinator.useScanWorkRecovery?.();
  const active = coordinator.useScanWorkStore(state => state.active);
  return <output>{active ? `${active.owner}:${active.path}` : "idle"}</output>;
}

test("startup, reconnect and dropped frames reconcile authoritative work state", async () => {
  backend.scanWorkStatus.mockResolvedValue({ active: work(), recent: [] });
  render(<RecoveryHarness />);
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("image:registry.local/app:1"));
  backend.scanWorkStatus.mockResolvedValue({ active: null, recent: [{ ...work(), status: "completed", runId: "saved-image" }] });
  await act(async () => handlers.get("transport://reconnected")?.({ payload: {} }));
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("idle"));
  backend.scanWorkStatus.mockResolvedValue({ active: work("replacement"), recent: [] });
  await act(async () => handlers.get("transport://lagged")?.({ payload: {} }));
  await waitFor(() => expect(coordinator.useScanWorkStore.getState().active?.operationId).toBe("replacement"));
});

test("a status request started before a work event cannot resurrect an old operation", async () => {
  let finish!: (snapshot: unknown) => void;
  backend.scanWorkStatus.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  render(<RecoveryHarness />);
  await waitFor(() => expect(handlers.has("work://changed")).toBe(true));
  await act(async () => handlers.get("work://changed")?.({ payload: { active: work("new-operation"), recent: [] } }));
  await act(async () => finish({ active: work("old-operation"), recent: [] }));
  expect(coordinator.useScanWorkStore.getState().active?.operationId).toBe("new-operation");
});

test("unmounting recovery invalidates a pending status response", async () => {
  let finish!: (snapshot: unknown) => void;
  backend.scanWorkStatus.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const view = render(<RecoveryHarness />);
  await waitFor(() => expect(finish).toBeDefined());
  view.unmount();
  await act(async () => finish({ active: work("obsolete-session"), recent: [] }));
  expect(coordinator.useScanWorkStore.getState().active).toBeNull();
});

test("a newer requested status takes priority even when an older request answers first", async () => {
  let first!: (snapshot: unknown) => void;
  let second!: (snapshot: unknown) => void;
  backend.scanWorkStatus.mockImplementationOnce(() => new Promise(resolve => { first = resolve; }))
    .mockImplementationOnce(() => new Promise(resolve => { second = resolve; }));
  render(<RecoveryHarness />);
  await waitFor(() => expect(handlers.has("transport://lagged")).toBe(true));
  await act(async () => handlers.get("transport://lagged")?.({ payload: {} }));
  await act(async () => first({ active: work("old-operation"), recent: [] }));
  await act(async () => second({ active: work("new-operation"), recent: [] }));
  expect(coordinator.useScanWorkStore.getState().active?.operationId).toBe("new-operation");
});
