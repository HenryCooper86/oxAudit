import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { DepsScanPage } from "./DepsScan";
import type { CanonicalProjectionMetadata, CanonicalRun, DependencyScanResult, LockfileInfo, Vulnerability } from "../lib/types";
import { api } from "../lib/api";
import { useAppStore, useToastStore } from "../lib/stores";
import { reconcileBackendWork, useScanWorkStore } from "../features/project-home/coordinator";

const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("../lib/events", () => ({ listen: async (name: string, handler: (event: { payload: unknown }) => void) => { listeners.set(name, handler); return () => listeners.delete(name); } }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

beforeEach(() => {
  vi.clearAllMocks(); listeners.clear();
  useToastStore.setState({ toasts: [] });
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

test("editing the target is a local draft that never activates the native project", async () => {
  const activate = vi.spyOn(api, "setActiveProject");
  render(<DepsScanPage />);
  fireEvent.change(screen.getByRole("textbox", { name: "Project folder path" }), { target: { value: "/first" } });
  fireEvent.change(screen.getByRole("textbox", { name: "Project folder path" }), { target: { value: "/pending" } });
  await act(async () => {});
  expect(activate).not.toHaveBeenCalled();
  expect(screen.getByRole("textbox", { name: "Project folder path" })).toHaveValue("/pending");
  expect(useAppStore.getState().activeProject).toBe("/repo");
  expect(useAppStore.getState().selectedProject).toBeNull();
});

test("externally selecting the current draft restores its saved receipt", async () => {
  vi.mocked(api.listCanonicalRuns).mockResolvedValueOnce([]).mockResolvedValue([{ ...savedDependencyRun, targetLabel: "/selected-draft" }]);
  vi.spyOn(api, "loadCanonicalProjectionMetadata").mockResolvedValue({
    kind: "pagedProjection", projectionKind: "dependencies",
    projection: { ...savedDependencyResult, summary: { ...savedDependencyResult.summary, path: "/selected-draft" } },
    sections: { vulnerabilities: 1 },
  });
  vi.spyOn(api, "loadCanonicalProjectionPage").mockResolvedValue(savedAdvisoryPage);
  render(<DepsScanPage />);
  await screen.findByText("No saved dependency results for this project.");
  fireEvent.change(screen.getByRole("textbox", { name: "Project folder path" }), { target: { value: "/selected-draft" } });

  await act(async () => useAppStore.getState().setActiveProject("/selected-draft"));
  expect(await screen.findByRole("heading", { name: "leaf" })).toBeInTheDocument();
  expect(screen.getByRole("textbox", { name: "Project folder path" })).toHaveValue("/selected-draft");
});

test("discovery clears unavailable runtime context without persisting the draft, then retries the same target", async () => {
  vi.mocked(api.setActiveProject).mockRejectedValueOnce(new Error("Project folder unavailable"));
  vi.spyOn(api, "findLockfiles").mockResolvedValue([{ path: "/typed-project/package-lock.json", kind: "npm", packages: 2 }]);
  render(<DepsScanPage />);
  fireEvent.change(screen.getByRole("textbox", { name: "Project folder path" }), { target: { value: "/typed-project" } });
  fireEvent.click(screen.getByRole("button", { name: "Find lockfiles" }));
  const retry = await screen.findByRole("button", { name: "Retry discovery" });
  expect(useAppStore.getState().activeProject).toBeNull();
  expect(useAppStore.getState().selectedProject).toBeNull();
  expect(useAppStore.getState().pageStatus["deps-scan"]?.tone).toBe("error");
  expect(screen.getByRole("textbox", { name: "Project folder path" })).toHaveValue("/typed-project");

  fireEvent.click(retry);
  expect(await screen.findByLabelText("Detected lockfiles")).toHaveTextContent("(2 pkgs)");
  expect(useAppStore.getState().activeProject).toBe("/typed-project");
  expect(useAppStore.getState().selectedProject).toBe("/typed-project");
  expect(screen.queryByRole("button", { name: "Retry discovery" })).not.toBeInTheDocument();
});

test("a failed explicit check clears unavailable runtime context and keeps its failure status", async () => {
  vi.mocked(api.setActiveProject).mockRejectedValueOnce(new Error("Project folder unavailable"));
  render(<DepsScanPage />);
  fireEvent.change(screen.getByRole("textbox", { name: "Project folder path" }), { target: { value: "/unavailable-project" } });
  fireEvent.click(screen.getByRole("button", { name: "Check dependencies" }));
  expect(await screen.findByRole("button", { name: "Retry dependency check" })).toBeEnabled();
  expect(useAppStore.getState().activeProject).toBeNull();
  expect(useAppStore.getState().selectedProject).toBeNull();
  expect(useAppStore.getState().pageStatus["deps-scan"]?.tone).toBe("error");
  expect(useScanWorkStore.getState().active).toBeNull();
  expect(screen.getByRole("textbox", { name: "Project folder path" })).toHaveValue("/unavailable-project");
});

test("discovery of a newly typed target keeps fresh inventory instead of restoring an older saved projection", async () => {
  const oldMetadata = deferred<CanonicalProjectionMetadata<DependencyScanResult>>();
  vi.mocked(api.listCanonicalRuns).mockResolvedValueOnce([]).mockResolvedValue([{ ...savedDependencyRun, targetLabel: "/typed-project" }]);
  vi.spyOn(api, "loadCanonicalProjectionMetadata").mockReturnValue(oldMetadata.promise);
  vi.spyOn(api, "loadCanonicalProjectionPage").mockResolvedValue(savedAdvisoryPage);
  vi.spyOn(api, "findLockfiles").mockResolvedValue([{ path: "/typed-project/package-lock.json", kind: "npm", packages: 12 }]);
  render(<DepsScanPage />);
  await screen.findByText("No saved dependency results for this project.");
  fireEvent.change(screen.getByRole("textbox", { name: "Project folder path" }), { target: { value: "/typed-project" } });
  fireEvent.click(screen.getByRole("button", { name: "Find lockfiles" }));
  expect(await screen.findByLabelText("Detected lockfiles")).toHaveTextContent("(12 pkgs)");
  await act(async () => reconcileBackendWork({ active: null, recent: [] }, true));

  await act(async () => oldMetadata.resolve({
    kind: "pagedProjection", projectionKind: "dependencies",
    projection: { ...savedDependencyResult, summary: { ...savedDependencyResult.summary, path: "/typed-project" } },
    sections: { vulnerabilities: 1 },
  }));
  expect(screen.getByLabelText("Detected lockfiles")).toHaveTextContent("(12 pkgs)");
  expect(screen.getByLabelText("Detected lockfiles")).not.toHaveTextContent("Pipfile.lock");
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

test("advisory detail promotes a proven ecosystem candidate to a recommended fix", async () => {
  const pypi: Vulnerability = {
    id: "GHSA-pypi", aliases: [], summary: "PyPI advisory", details: "detail", severity: "high",
    cvssScore: 7, epss: null, epssPercentile: null, knownExploited: false, ransomware: false, publicExploit: false,
    directUsage: { referenced: null, referencedFiles: 0, exampleFile: null },
    ecosystem: "PyPI", packageName: "leaf", installedVersion: "1.0.0", fixedVersions: ["1.0.1"],
    affectedRange: null, references: [], published: null, modified: null, lockfile: "/repo/Pipfile.lock",
    occurrence: { installPath: "site-packages/leaf", status: "available", warnings: [], paths: [{ workspace: "", entryPoint: "leaf", chain: [{ name: "leaf", packageName: "leaf", installPath: "site-packages/leaf", dependencyType: "runtime", declared: "==1.0.0" }] }] },
    affectedEvidence: { ecosystem: "PyPI", packageName: "leaf", records: [{ package: { ecosystem: "PyPI", name: "leaf" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.0.1" }] }] }] },
  };
  const result: DependencyScanResult = {
    summary: { path: "/repo", lockfilesFound: ["/repo/Pipfile.lock"], packagesFound: 1, packagesQueried: 1, vulnerabilitiesFound: 1, durationMs: 0 },
    dependencies: [],
    vulnerabilities: [pypi],
  };
  useAppStore.getState().openProject("/repo", "deps-scan", undefined, result);
  render(<DepsScanPage />);
  expect(await screen.findByText("Fix: upgrade to 1.0.1")).toBeInTheDocument();
});

test("advisory detail keeps raw fixed-version chips when no candidate is proven", async () => {
  const legacy: Vulnerability = {
    id: "GHSA-none", aliases: [], summary: "advisory without range evidence", details: "detail", severity: "medium",
    cvssScore: null, epss: null, epssPercentile: null, knownExploited: false, ransomware: false, publicExploit: false,
    directUsage: { referenced: null, referencedFiles: 0, exampleFile: null },
    ecosystem: "npm", packageName: "leaf", installedVersion: "1.0.0", fixedVersions: ["2.0.0"],
    affectedRange: null, references: [], published: null, modified: null, lockfile: "/repo/package-lock.json",
    occurrence: { installPath: "node_modules/leaf", status: "available", warnings: [], paths: [] },
    affectedEvidence: null,
  };
  const result: DependencyScanResult = {
    summary: { path: "/repo", lockfilesFound: ["/repo/package-lock.json"], packagesFound: 1, packagesQueried: 1, vulnerabilitiesFound: 1, durationMs: 0 },
    dependencies: [],
    vulnerabilities: [legacy],
  };
  useAppStore.getState().openProject("/repo", "deps-scan", undefined, result);
  render(<DepsScanPage />);
  expect(await screen.findByText("Advisory-reported fixed versions")).toBeInTheDocument();
  expect((await screen.findAllByText("2.0.0")).length).toBeGreaterThan(0);
  expect(screen.queryByText(/^Fix: upgrade to/)).not.toBeInTheDocument();
});

const pypiAdvisory: Vulnerability = {
  id: "GHSA-pypi", aliases: [], summary: "PyPI advisory", details: "detail", severity: "high",
  cvssScore: 7, epss: null, epssPercentile: null, knownExploited: false, ransomware: false, publicExploit: false,
  directUsage: { referenced: null, referencedFiles: 0, exampleFile: null },
  ecosystem: "PyPI", packageName: "leaf", installedVersion: "1.0.0", fixedVersions: ["1.0.1"],
  affectedRange: null, references: [], published: null, modified: null, lockfile: "/repo/Pipfile.lock",
  occurrence: { installPath: "site-packages/leaf", status: "available", warnings: [], paths: [] },
  affectedEvidence: null,
};
const savedDependencyResult: DependencyScanResult = {
  summary: { path: "/repo", lockfilesFound: ["/repo/Pipfile.lock"], packagesFound: 1, packagesQueried: 1, vulnerabilitiesFound: 1, durationMs: 5 },
  dependencies: [],
  vulnerabilities: [pypiAdvisory],
};
const savedDependencyRun: CanonicalRun = {
  id: "run-deps-1", kind: "dependencies", targetLabel: "/repo", state: "completed", attempt: 1,
  createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [],
};
const savedAdvisoryPage = { items: [pypiAdvisory], offset: 0, limit: 50, filteredTotal: 1, total: 1 };

/** Typed view of the runtime `Promise.withResolvers`; the ES2020 lib predates its typings. */
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (reason?: unknown) => void } {
  // Unexpressible under the ES2020 lib: every runtime target here ships `withResolvers`.
  const constructor = Promise as unknown as {
    withResolvers<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (reason?: unknown) => void };
  };
  return constructor.withResolvers<T>();
}

test("cancelling a dependency check is neutral, preserves the restored evidence and never offers a retry", async () => {
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([savedDependencyRun]);
  vi.spyOn(api, "loadCanonicalProjectionMetadata").mockResolvedValue({
    kind: "pagedProjection", projectionKind: "dependencies", projection: savedDependencyResult, sections: { vulnerabilities: 1 },
  });
  vi.spyOn(api, "loadCanonicalProjectionPage").mockResolvedValue(savedAdvisoryPage);
  vi.spyOn(api, "cancelScanWork").mockResolvedValue(true);
  const { promise: scanPromise, reject: rejectScan } = deferred<DependencyScanResult>();
  const scan = vi.spyOn(api, "scanDependencies").mockImplementation(() => scanPromise);
  render(<DepsScanPage />);
  await waitFor(() => expect(useAppStore.getState().pageStatus["deps-scan"]?.label).toContain("Saved dependency results"));
  expect(await screen.findByRole("heading", { name: "leaf" })).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Check dependencies" }));
  await waitFor(() => expect(scan).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  await act(async () => { rejectScan("dependency scan cancelled"); });

  expect(await screen.findByText("Latest operation cancelled")).toBeInTheDocument();
  expect(useAppStore.getState().pageStatus["deps-scan"]).toMatchObject({ label: "Dependency check cancelled", tone: "neutral" });
  expect(screen.queryByText("Dependency checking failed")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Retry dependency check" })).not.toBeInTheDocument();
  expect(useToastStore.getState().toasts).toHaveLength(0);
  expect(await screen.findByRole("heading", { name: "leaf" })).toBeInTheDocument();
});

test("a selected project without saved results shows the no-saved-results state instead of the choose-project prompt", async () => {
  const scan = vi.spyOn(api, "scanDependencies").mockResolvedValue(savedDependencyResult);
  render(<DepsScanPage />);

  expect(await screen.findByText("No saved dependency results for this project.")).toBeInTheDocument();
  expect(screen.queryByText("Choose a project to detect supported lockfiles.")).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Check dependencies" }));
  await waitFor(() => expect(scan).toHaveBeenCalledWith("/repo", false, null, expect.any(String)));
  expect(await screen.findByRole("heading", { name: "leaf" })).toBeInTheDocument();
});

test("a failed saved-history load surfaces the failure with an in-page retry and recovers", async () => {
  const metadata = vi.spyOn(api, "loadCanonicalProjectionMetadata")
    .mockRejectedValueOnce(new Error("corrupt projection"))
    .mockResolvedValueOnce({
      kind: "pagedProjection", projectionKind: "dependencies", projection: savedDependencyResult, sections: { vulnerabilities: 1 },
    });
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([savedDependencyRun]);
  vi.spyOn(api, "loadCanonicalProjectionPage").mockResolvedValue(savedAdvisoryPage);
  render(<DepsScanPage />);

  expect(await screen.findByText("Saved dependency results could not be loaded.")).toBeInTheDocument();
  expect(screen.getByText(/corrupt projection/)).toBeInTheDocument();
  expect(screen.queryByText("Choose a project to detect supported lockfiles.")).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Retry loading saved results" }));
  expect(await screen.findByRole("heading", { name: "leaf" })).toBeInTheDocument();
  expect(metadata).toHaveBeenCalledTimes(2);
  await waitFor(() => expect(useAppStore.getState().pageStatus["deps-scan"]?.label).toContain("Saved dependency results"));
});

test("enabling the local advisory database blocks checking until the default path resolves, then scans with it", async () => {
  const { promise: defaultPathPromise, resolve: resolveDefault } = deferred<string>();
  vi.spyOn(api, "defaultAdvisoryDbPath").mockImplementation(() => defaultPathPromise);
  const scan = vi.spyOn(api, "scanDependencies").mockResolvedValue(savedDependencyResult);
  render(<DepsScanPage />);
  await screen.findByText("No saved dependency results for this project.");

  fireEvent.click(screen.getByRole("switch", { name: "Local advisory database" }));
  const check = () => screen.getAllByRole("button", { name: "Check dependencies" })[0];
  expect(check()).toBeDisabled();
  expect(screen.getByText("Looking up the default advisory database")).toBeInTheDocument();

  await act(async () => { resolveDefault("/data/advisories.sqlite3"); });
  await waitFor(() => expect(check()).toBeEnabled());
  expect(screen.getByLabelText("Advisory database path")).toHaveValue("/data/advisories.sqlite3");
  expect(screen.queryByText("Looking up the default advisory database")).not.toBeInTheDocument();

  fireEvent.click(check());
  await waitFor(() => expect(scan).toHaveBeenCalledWith("/repo", false, "/data/advisories.sqlite3", expect.any(String)));
});

test("a failed default advisory path lookup stays visible and blocked until a usable path is entered", async () => {
  vi.spyOn(api, "defaultAdvisoryDbPath").mockRejectedValueOnce(new Error("home directory unavailable"));
  const scan = vi.spyOn(api, "scanDependencies").mockResolvedValue(savedDependencyResult);
  render(<DepsScanPage />);
  await screen.findByText("No saved dependency results for this project.");

  fireEvent.click(screen.getByRole("switch", { name: "Local advisory database" }));
  expect(await screen.findByText("Local advisory database needs a path")).toBeInTheDocument();
  expect(screen.getByText(/home directory unavailable/)).toBeInTheDocument();
  const check = () => screen.getAllByRole("button", { name: "Check dependencies" })[0];
  expect(check()).toBeDisabled();

  fireEvent.change(screen.getByLabelText("Advisory database path"), { target: { value: "/custom/advisories.sqlite3" } });
  await waitFor(() => expect(check()).toBeEnabled());
  expect(screen.queryByText("Local advisory database needs a path")).not.toBeInTheDocument();

  fireEvent.click(check());
  await waitFor(() => expect(scan).toHaveBeenCalledWith("/repo", false, "/custom/advisories.sqlite3", expect.any(String)));
});

test("an enabled local database blocks retry and recheck until its path is usable", async () => {
  useAppStore.getState().openProject("/repo", "deps-scan", undefined, savedDependencyResult);
  vi.spyOn(api, "defaultAdvisoryDbPath").mockRejectedValueOnce("Default path unavailable");
  const scan = vi.spyOn(api, "scanDependencies")
    .mockRejectedValueOnce("Advisory service unavailable")
    .mockResolvedValueOnce(savedDependencyResult);
  render(<DepsScanPage />);
  await screen.findByRole("button", { name: "Recheck dependencies" });
  fireEvent.click(screen.getByRole("button", { name: "Check dependencies" }));
  await screen.findByRole("button", { name: "Retry dependency check" });

  fireEvent.click(screen.getByRole("switch", { name: "Local advisory database" }));
  await screen.findByText("Local advisory database needs a path");
  expect(screen.getByRole("button", { name: "Retry dependency check" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Recheck dependencies" })).toBeDisabled();

  fireEvent.change(screen.getByLabelText("Advisory database path"), { target: { value: "/data/advisories.sqlite3" } });
  expect(screen.getByRole("button", { name: "Recheck dependencies" })).toBeEnabled();
  fireEvent.click(screen.getByRole("button", { name: "Retry dependency check" }));
  await waitFor(() => expect(scan).toHaveBeenLastCalledWith("/repo", false, "/data/advisories.sqlite3", expect.any(String)));
  expect(await screen.findByRole("heading", { name: "leaf" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Retry dependency check" })).not.toBeInTheDocument();
});

test("retrying discovery keeps its fresh lockfiles instead of restoring older inventory", async () => {
  const pending = deferred<LockfileInfo[]>();
  vi.mocked(api.listCanonicalRuns).mockResolvedValueOnce([]).mockResolvedValue([savedDependencyRun]);
  vi.spyOn(api, "loadCanonicalProjectionMetadata").mockResolvedValue({
    kind: "pagedProjection", projectionKind: "dependencies", projection: savedDependencyResult, sections: { vulnerabilities: 1 },
  });
  vi.spyOn(api, "loadCanonicalProjectionPage").mockResolvedValue(savedAdvisoryPage);
  vi.spyOn(api, "findLockfiles")
    .mockRejectedValueOnce("Discovery temporarily unavailable")
    .mockReturnValueOnce(pending.promise);
  render(<DepsScanPage />);
  await screen.findByText("No saved dependency results for this project.");
  fireEvent.click(screen.getByRole("button", { name: "Find lockfiles" }));
  await screen.findByRole("button", { name: "Retry discovery" });
  fireEvent.click(screen.getByRole("button", { name: "Retry discovery" }));
  await act(async () => {});
  expect(useAppStore.getState().pageStatus["deps-scan"]?.tone).toBe("running");

  await act(async () => pending.resolve([{ path: "/repo/package-lock.json", kind: "npm", packages: 12 }]));
  const detected = screen.getByLabelText("Detected lockfiles");
  expect(detected).toHaveTextContent("package-lock.json");
  expect(detected).toHaveTextContent("(12 pkgs)");
  expect(detected).not.toHaveTextContent("Pipfile.lock");
  expect(screen.queryByText("GHSA-pypi")).not.toBeInTheDocument();
});

test("a completed scan keeps its fresh full inventory when the backend terminal reconcile lands", async () => {
  const full: DependencyScanResult = {
    summary: {
      path: "/repo", runId: "run-fresh", lockfilesFound: ["/repo/package-lock.json"],
      packagesFound: 2, packagesQueried: 2, vulnerabilitiesFound: 0, durationMs: 4,
    },
    dependencies: [
      { ecosystem: "npm", name: "a", version: "1.0.0", lockfile: "/repo/package-lock.json" },
      { ecosystem: "npm", name: "b", version: "2.0.0", lockfile: "/repo/package-lock.json" },
    ],
    vulnerabilities: [],
  };
  const summaryOnly: DependencyScanResult = { ...full, dependencies: [], vulnerabilities: [] };
  vi.mocked(api.listCanonicalRuns).mockResolvedValueOnce([]).mockResolvedValue([{ ...savedDependencyRun, id: "run-fresh" }]);
  vi.spyOn(api, "loadCanonicalProjectionMetadata").mockResolvedValue({
    kind: "pagedProjection", projectionKind: "dependencies", projection: summaryOnly, sections: { vulnerabilities: 0 },
  });
  vi.spyOn(api, "loadCanonicalProjectionPage").mockResolvedValue({ items: [], offset: 0, limit: 50, filteredTotal: 0, total: 0 });
  vi.spyOn(api, "scanDependencies").mockResolvedValue(full);
  render(<DepsScanPage />);
  await screen.findByText("No saved dependency results for this project.");
  fireEvent.click(screen.getByRole("button", { name: "Check dependencies" }));
  expect(await screen.findByLabelText("Detected lockfiles")).toHaveTextContent("(2 pkgs)");

  // The backend confirms this very run as terminal; the page must keep the
  // fresh full inventory instead of swapping in the summary-only projection.
  await act(async () => {
    reconcileBackendWork({
      active: null,
      recent: [{ operationId: "op-fresh", kind: "dependencies", target: "/repo", status: "completed", runId: "run-fresh", startedAtMs: 1, updatedAtMs: 2 }],
    });
  });
  expect(screen.getByLabelText("Detected lockfiles")).toHaveTextContent("(2 pkgs)");
  expect(screen.queryByText("Load complete upgrade decisions")).not.toBeInTheDocument();
  expect(useAppStore.getState().pageStatus["deps-scan"]?.label).toContain("Dependencies checked");
});

test("a newer backend dependency run for the same target supersedes the in-memory receipt", async () => {
  const full: DependencyScanResult = {
    summary: {
      path: "/repo", runId: "run-fresh", lockfilesFound: ["/repo/package-lock.json"],
      packagesFound: 2, packagesQueried: 2, vulnerabilitiesFound: 0, durationMs: 4,
    },
    dependencies: [
      { ecosystem: "npm", name: "a", version: "1.0.0", lockfile: "/repo/package-lock.json" },
      { ecosystem: "npm", name: "b", version: "2.0.0", lockfile: "/repo/package-lock.json" },
    ],
    vulnerabilities: [],
  };
  vi.mocked(api.listCanonicalRuns).mockResolvedValueOnce([]).mockResolvedValue([{ ...savedDependencyRun, id: "run-newer" }]);
  vi.spyOn(api, "loadCanonicalProjectionMetadata").mockResolvedValue({
    kind: "pagedProjection", projectionKind: "dependencies",
    projection: { ...full, dependencies: [], vulnerabilities: [], summary: { ...full.summary, runId: "run-newer" } },
    sections: { vulnerabilities: 0 },
  });
  vi.spyOn(api, "loadCanonicalProjectionPage").mockResolvedValue({ items: [], offset: 0, limit: 50, filteredTotal: 0, total: 0 });
  vi.spyOn(api, "scanDependencies").mockResolvedValue(full);
  render(<DepsScanPage />);
  await screen.findByText("No saved dependency results for this project.");
  fireEvent.click(screen.getByRole("button", { name: "Check dependencies" }));
  expect(await screen.findByLabelText("Detected lockfiles")).toHaveTextContent("(2 pkgs)");

  // A newer completed run for the same target must replace the receipt.
  await act(async () => {
    reconcileBackendWork({
      active: null,
      recent: [{ operationId: "op-newer", kind: "dependencies", target: "/repo", status: "completed", runId: "run-newer", startedAtMs: 3, updatedAtMs: 4 }],
    });
  });
  expect(await screen.findByText("Load complete upgrade decisions")).toBeInTheDocument();
  expect(useAppStore.getState().pageStatus["deps-scan"]?.label).toContain("Saved dependency results");
});
