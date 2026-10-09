import { create } from "zustand";
import { normalizeCommandError } from "../../lib/commandError";
import { api } from "../../lib/api";
import {
  buildSourceScanRequest,
  createSourceScanOptions,
} from "../../lib/sourceScanOptions";
import type {
  DependencyScanResult,
  ScanRunDetail,
  ScanSettings,
  ScanWorkKind,
  ScanWorkSnapshot,
  ScanWorkStatus,
} from "../../lib/types";
export { useScanWorkRecovery } from "./scanWorkRecovery";

type Owner = "project" | ScanWorkKind;
interface ActiveScan {
  id: number;
  operationId: string;
  owner: Owner;
  path: string;
  stage: string;
  cancelling: boolean;
  cancel: () => Promise<void>;
  recovered: boolean;
  backendObserved: boolean;
  terminalStatus?: ScanWorkStatus;
}
export interface ProjectCheck {
  path: string;
  status: "running" | "completed" | "failed" | "cancelled" | "incomplete";
  source: string;
  dependencies: string;
  sourceResult?: ScanRunDetail;
  dependencyResult?: DependencyScanResult;
  error?: string;
}
export const useScanWorkStore = create<{
  active: ActiveScan | null;
  check: ProjectCheck | null;
  checkOwnerId: number | null;
  backend: ScanWorkSnapshot;
  backendEpoch: number;
  recoveryRevision: number;
  recoveryError: string | null;
  lastTargets: Partial<Record<ScanWorkKind, string>>;
}>(() => ({ active: null, check: null, checkOwnerId: null, backend: { active: null, recent: [] }, backendEpoch: 0,
  recoveryRevision: 0, recoveryError: null, lastTargets: {} }));

const WORK_LABELS: Record<ScanWorkKind, string> = {
  source: "Scanning source", dependencies: "Checking dependencies", binary: "Scanning binaries",
  image: "Scanning image", history: "Scanning git history",
};

function validWorkSnapshot(value: unknown): value is ScanWorkSnapshot {
  if (!value || typeof value !== "object") return false;
  const snapshot = value as ScanWorkSnapshot;
  const statuses: ScanWorkStatus[] = ["running", "cancelling", "completed", "failed", "cancelled", "incomplete"];
  const descriptor = (work: unknown) => {
    if (!work || typeof work !== "object") return false;
    const item = work as ScanWorkSnapshot["recent"][number];
    return typeof item.operationId === "string" && item.operationId.length > 0
      && Object.prototype.hasOwnProperty.call(WORK_LABELS, item.kind) && statuses.includes(item.status)
      && typeof item.target === "string" && Number.isFinite(item.startedAtMs) && Number.isFinite(item.updatedAtMs)
      && (item.runId === undefined || item.runId === null || typeof item.runId === "string");
  };
  return Array.isArray(snapshot.recent) && snapshot.recent.every(descriptor)
    && (snapshot.active === null || (descriptor(snapshot.active) && ["running", "cancelling"].includes(snapshot.active.status)));
}

/** Backend events never retire a local promise before its result can publish. */
export function reconcileBackendWork(snapshot: unknown, forceRevision = false): void {
  if (!validWorkSnapshot(snapshot)) {
    invalidateWorkStatusRequests();
    useScanWorkStore.setState({ recoveryError: "Scan work updates unavailable: invalid backend work status." });
    return;
  }
  useScanWorkStore.setState(state => {
    const changed = JSON.stringify(state.backend) !== JSON.stringify(snapshot);
    let active = state.active;
    if (snapshot.active) {
      const work = snapshot.active;
      if (active?.operationId === work.operationId) {
        active = { ...active, backendObserved: true, cancelling: active.cancelling || work.status === "cancelling" };
      } else {
        active = { id: ++sequence, operationId: work.operationId, owner: work.kind, path: work.target,
          stage: WORK_LABELS[work.kind], cancelling: work.status === "cancelling", recovered: true,
          backendObserved: true, cancel: async () => { await api.cancelScanWork(work.operationId); } };
      }
    } else if (active?.recovered) {
      active = null;
    } else if (active) {
      const terminal = snapshot.recent.find(work => work.operationId === active!.operationId);
      if (terminal) active = { ...active, backendObserved: true, terminalStatus: terminal.status };
      else if (active.backendObserved) active = null;
    }
    const interrupted = state.active?.owner === "project" && state.active.id !== active?.id
      && state.checkOwnerId === state.active.id && state.check?.status === "running";
    const check = interrupted && state.check ? {
      ...state.check, status: "incomplete" as const,
      source: state.check.source === "running" ? "interrupted" : state.check.source,
      dependencies: state.check.dependencies === "running" ? "interrupted" : state.check.dependencies === "pending" ? "not run" : state.check.dependencies,
      error: "Project check interrupted by a backend ownership change. Saved evidence remains available.",
    } : state.check;
    return { active, check, backend: snapshot, backendEpoch: state.backendEpoch + 1,
      recoveryRevision: state.recoveryRevision + (changed || forceRevision ? 1 : 0), recoveryError: null,
      lastTargets: snapshot.active ? { ...state.lastTargets, [snapshot.active.kind]: snapshot.active.target } : state.lastTargets };
  });
}

/** Returns the ID for one lease; stale callers cannot bind replacement work. */
export function scanOperationId(ownership: number): string | undefined {
  const active = useScanWorkStore.getState().active;
  return active?.id === ownership ? active.operationId : undefined;
}

let statusRequestSequence = 0;
export function invalidateWorkStatusRequests(): void {
  statusRequestSequence += 1;
}
export async function refreshScanWork(forceRevision = false): Promise<void> {
  const request = ++statusRequestSequence;
  const epoch = useScanWorkStore.getState().backendEpoch;
  try {
    const snapshot = await api.scanWorkStatus();
    if (request === statusRequestSequence && epoch === useScanWorkStore.getState().backendEpoch) reconcileBackendWork(snapshot, forceRevision);
  } catch (error) {
    if (request === statusRequestSequence && epoch === useScanWorkStore.getState().backendEpoch) useScanWorkStore.setState({ recoveryError: String(error) });
  }
}
function withSavedSourceReceipt(
  check: ProjectCheck,
  path: string,
  saved: ScanRunDetail,
): ProjectCheck {
  if (
    check.path !== path ||
    check.sourceResult?.projectId !== saved.projectId ||
    check.sourceResult?.runId !== saved.runId ||
    check.sourceResult.persistence.status !== "notSaved" ||
    saved.persistence.status !== "saved"
  )
    return check;
  const source =
    check.source === "completed, not saved" ? "completed" : check.source;
  const status =
    check.status === "incomplete" &&
    source === "completed" &&
    (check.dependencies === "completed" ||
      check.dependencies === "not applicable")
      ? "completed"
      : check.status;
  return { ...check, sourceResult: saved, source, status };
}

/** Reconcile persistence only; a save cannot turn failed/cancelled work into success. */
export function reconcileSourceRunSave(
  path: string,
  saved: ScanRunDetail,
): void {
  useScanWorkStore.setState((state) => ({
    check: state.check
      ? withSavedSourceReceipt(state.check, path, saved)
      : null,
  }));
}

let sequence = 0;
export function acquireScan(
  owner: Owner,
  path: string,
  stage: string,
): number | null {
  if (useScanWorkStore.getState().active) return null;
  const id = ++sequence;
  const operationId = crypto.randomUUID();
  useScanWorkStore.setState({
    active: {
      id,
      operationId,
      owner,
      path,
      stage,
      cancelling: false,
      recovered: false,
      backendObserved: false,
      cancel: async () => { await api.cancelScanWork(operationId); },
    },
    ...(owner === "project" ? {} : { lastTargets: { ...useScanWorkStore.getState().lastTargets, [owner]: path } }),
  });
  return id;
}
export function releaseScan(id: number) {
  const state = useScanWorkStore.getState();
  if (state.active?.id !== id) return;
  if (state.backend.active?.operationId === state.active.operationId) {
    useScanWorkStore.setState({ active: { ...state.active, recovered: true } });
  } else useScanWorkStore.setState({ active: null });
}
/** A page can leave while native work continues; backend snapshots then own its lease. */
export function detachScan(id: number): void {
  const active = useScanWorkStore.getState().active;
  if (active?.id === id) useScanWorkStore.setState({ active: { ...active, recovered: true } });
}
export async function cancelActiveScan() {
  const active = useScanWorkStore.getState().active;
  if (!active || active.cancelling) return;
  useScanWorkStore.setState({ active: { ...active, cancelling: true } });
  try {
    await api.cancelScanWork(active.operationId);
    void refreshScanWork();
  } catch (error) {
    const current = useScanWorkStore.getState().active;
    if (current?.id === active.id)
      useScanWorkStore.setState({
        active: { ...current, cancelling: false },
        ...(current.owner === "project"
          ? {
              check: {
                ...useScanWorkStore.getState().check!,
                error: `Cancellation failed: ${String(error)}`,
              },
            }
          : {}),
      });
  }
}
/** Module-owned work outlives page mounts; ownership lasts until native work settles. */
export async function startProjectCheck(
  path: string,
  settings: ScanSettings | null,
) {
  const id = acquireScan("project", path, "Inspecting project");
  if (id === null) return;
  useScanWorkStore.setState({ checkOwnerId: id });
  const previous = useScanWorkStore.getState().check;
  const previousResults =
    previous?.path === path
      ? {
          sourceResult: previous.sourceResult,
          dependencyResult: previous.dependencyResult,
        }
      : {};
  let result: ProjectCheck = {
    ...previousResults,
    path,
    status: "running",
    source: "pending",
    dependencies: "pending",
  };
  const publish = () => {
    const state = useScanWorkStore.getState();
    if (state.active?.id !== id && state.checkOwnerId !== id) return;
    // Retry-save may finish on the source page while dependencies are running.
    // Carry that matching saved receipt into this coordinator's next outcome.
    if (state.check?.sourceResult) {
      result = withSavedSourceReceipt(
        result,
        state.check.path,
        state.check.sourceResult,
      );
    }
    useScanWorkStore.setState({ check: { ...result } });
  };
  const assertCurrent = () => {
    const active = useScanWorkStore.getState().active;
    if (active?.id !== id) throw new Error("Project check interrupted by a backend ownership change");
    if (active.cancelling)
      throw new Error("Project check cancelled");
  };
  const stage = (
    label: string,
    startsNative = false,
  ) => {
    assertCurrent();
    const active = useScanWorkStore.getState().active!;
    const operationId = startsNative ? crypto.randomUUID() : active.operationId;
    useScanWorkStore.setState({
      active: { ...active, operationId, path: result.path, stage: label,
        backendObserved: startsNative ? false : active.backendObserved,
        terminalStatus: undefined, cancel: async () => { await api.cancelScanWork(operationId); } },
    });
    publish();
  };
  publish();
  try {
    if (!settings)
      throw new Error(
        "Settings could not be loaded. Open Settings, save usable scan settings, and retry.",
      );
    const context = await api.inspectSourceProject(path);
    assertCurrent();
    result.path = context.canonicalPath;
    const options = context.lastOptions
      ? {
          ...context.lastOptions,
          path: context.canonicalPath,
          ignoreInvalidPolicy: false,
        }
      : buildSourceScanRequest(
          context.canonicalPath,
          createSourceScanOptions(settings),
        );
    if (!options.scanSecrets && !options.scanVulnerabilities)
      throw new Error(
        "Enable a source scan category in Source Scan or Settings before checking this project.",
      );
    if (context.policy.status === "invalid")
      throw new Error(
        "Project policy is invalid. Review it in Source Scan before checking the project.",
      );
    // Inspection validates the explicit scan root. A background check does not
    // own the user's current assistant/runtime selection.
    result.source = "running";
    stage("Scanning source", true);
    result.sourceResult = await api.scanProject(options, scanOperationId(id));
    assertCurrent();
    if (result.sourceResult.status !== "completed")
      throw new Error(
        "Source scan did not complete. Previous results remain available.",
      );
    result.source =
      result.sourceResult.persistence.status === "saved"
        ? "completed"
        : "completed, not saved";
    stage("Finding lockfiles");
    const lockfiles = await api.findLockfiles(context.canonicalPath);
    assertCurrent();
    if (lockfiles.length === 0) result.dependencies = "not applicable";
    else {
      result.dependencies = "running";
      stage("Checking dependencies", true);
      result.dependencyResult = await api.scanDependencies(
        context.canonicalPath, false, null, scanOperationId(id),
      );
      assertCurrent();
      result.dependencies =
        result.dependencyResult.summary.advisoryCoverage === "complete"
          ? "completed"
          : "coverage unknown";
    }
    result.status =
      result.source === "completed" &&
      result.dependencies !== "coverage unknown"
        ? "completed"
        : "incomplete";
  } catch (error) {
    const cancelled =
      useScanWorkStore.getState().active?.cancelling ||
      String(error).includes("Project check cancelled");
    const interrupted = useScanWorkStore.getState().active?.id !== id;
    result.status = interrupted ? "incomplete" : cancelled ? "cancelled" : "failed";
    result.error = normalizeCommandError(error).message;
    if (result.source === "running")
      result.source = result.sourceResult?.status === "completed" ? (result.sourceResult.persistence.status === "saved" ? "completed" : "completed, not saved") : interrupted ? "interrupted" : cancelled ? "cancelled" : "failed";
    if (result.dependencies === "running")
      result.dependencies = interrupted ? "interrupted" : cancelled ? "cancelled" : "failed";
    else if (result.dependencies === "pending") result.dependencies = "not run";
  } finally {
    publish();
    releaseScan(id);
  }
}
