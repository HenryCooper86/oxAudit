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
} from "../../lib/types";

type Owner = "project" | "source" | "dependencies";
interface ActiveScan {
  id: number;
  owner: Owner;
  path: string;
  stage: string;
  cancelling: boolean;
  cancel: () => Promise<void>;
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
}>(() => ({ active: null, check: null }));
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
  useScanWorkStore.setState({
    active: {
      id,
      owner,
      path,
      stage,
      cancelling: false,
      cancel:
        owner === "source"
          ? api.cancelScan
          : owner === "dependencies"
            ? api.cancelDependencyScan
            : async () => {},
    },
  });
  return id;
}
export function releaseScan(id: number) {
  if (useScanWorkStore.getState().active?.id === id)
    useScanWorkStore.setState({ active: null });
}
export async function cancelActiveScan() {
  const active = useScanWorkStore.getState().active;
  if (!active || active.cancelling) return;
  useScanWorkStore.setState({ active: { ...active, cancelling: true } });
  try {
    await active.cancel();
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
    if (state.active?.id !== id) return;
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
    if (active?.id !== id || active.cancelling)
      throw new Error("Project check cancelled");
  };
  const stage = (
    label: string,
    cancel: () => Promise<void> = async () => {},
  ) => {
    assertCurrent();
    const active = useScanWorkStore.getState().active!;
    useScanWorkStore.setState({
      active: { ...active, path: result.path, stage: label, cancel },
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
    stage("Scanning source", api.cancelScan);
    result.sourceResult = await api.scanProject(options);
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
      stage("Checking dependencies", api.cancelDependencyScan);
      result.dependencyResult = await api.scanDependencies(
        context.canonicalPath,
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
    result.status = cancelled ? "cancelled" : "failed";
    result.error = normalizeCommandError(error).message;
    if (result.source === "running")
      result.source = cancelled ? "cancelled" : "failed";
    if (result.dependencies === "running")
      result.dependencies = cancelled ? "cancelled" : "failed";
    else if (result.dependencies === "pending") result.dependencies = "not run";
  } finally {
    publish();
    releaseScan(id);
  }
}
