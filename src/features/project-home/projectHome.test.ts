import {
  projectSettings,
  projectContext,
  sourceResult,
  dependencyResult,
} from "../../../tests/fixtures/projectHome";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../../lib/api";
import { loadProjectHome, parseSelectedProject } from "./history";
import {
  startProjectCheck,
  cancelActiveScan,
  useScanWorkStore,
  acquireScan,
  releaseScan,
} from "./coordinator";
import type { CanonicalRun, RecentProject } from "../../lib/types";
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
const settings = projectSettings.scan;
const context = { ...projectContext("/real/project"), projectId: "p" };
const source = { ...sourceResult(), projectId: "p" };
const recent: RecentProject = {
  projectId: "p",
  canonicalPath: "/real/project",
  displayName: "project",
  lastOpenedAt: "2026-09-07",
  lastCompletedAt: "2026-09-06",
  lastCompletedRunId: "s",
  openFindings: 2,
  critical: 1,
  high: 1,
};
const canonical = (
  id: string,
  kind: CanonicalRun["kind"],
  targetLabel: string,
  state: CanonicalRun["state"],
  time: number,
): CanonicalRun => ({
  id,
  kind,
  targetLabel,
  state,
  createdAtMs: time,
  updatedAtMs: time,
  attempt: 1,
  engineIds: [],
  rulePackIds: [],
  providerSnapshotIds: [],
  warnings: [],
});
beforeEach(() => {
  useScanWorkStore.setState({ active: null, check: null });
});
test("selection parsing rejects malformed storage without granting runtime authority", () => {
  for (const input of [
    null,
    '"/a"',
    '{"version":1,"path":4}',
    '{"version":1,"path":"  "}',
    "{",
  ])
    expect(parseSelectedProject(input)).toBeNull();
  expect(parseSelectedProject('{"version":1,"path":"/a"}')).toBe("/a");
});
test("durable home maps source IDs through projects and keeps latest failed dependency attempt separate from completed evidence", async () => {
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([recent]);
  vi.spyOn(api, "listSourceRuns").mockResolvedValue([
    {
      runId: "s",
      projectId: "p",
      status: "completed",
      startedAt: "2026-09-06",
      completedAt: "2026-09-06",
      totalFindings: 3,
      newFindings: 2,
      resolvedFindings: 0,
    },
  ]);
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([
    canonical("bad", "dependencies", "/deps-only", "failed", 30),
    canonical("ok", "dependencies", "/deps-only", "completed", 20),
    canonical("s", "source", "project", "completed", 10),
  ]);
  const homes = await loadProjectHome();
  expect(homes.map((p) => p.path).sort()).toEqual([
    "/deps-only",
    "/real/project",
  ]);
  const deps = homes.find((p) => p.path === "/deps-only")!;
  expect(deps.source).toBeNull();
  expect(deps.dependencies?.state).toBe("failed");
  expect(deps.completedDependencies?.id).toBe("ok");
  const src = homes.find((p) => p.path === "/real/project")!;
  expect(src.source?.openFindings).toBe(2);
  expect(src.newFindings).toBe(2);
  expect(src.dependencies).toBeNull();
});
function mockCheck() {
  vi.spyOn(api, "inspectSourceProject").mockResolvedValue(context);
  vi.spyOn(api, "setActiveProject").mockResolvedValue();
  vi.spyOn(api, "scanProject").mockResolvedValue(source);
  vi.spyOn(api, "findLockfiles").mockResolvedValue([
    { path: "/real/project/package-lock.json", kind: "npm", packages: 1 },
  ]);
  vi.spyOn(api, "scanDependencies").mockResolvedValue({
    summary: {
      path: "/real/project",
      lockfilesFound: ["package-lock.json"],
      packagesFound: 1,
      packagesQueried: 1,
      vulnerabilitiesFound: 0,
      durationMs: 1,
      advisoryCoverage: "complete",
    },
    dependencies: [],
    vulnerabilities: [],
  });
  vi.spyOn(api, "cancelScan").mockResolvedValue();
  vi.spyOn(api, "cancelDependencyScan").mockResolvedValue();
}
test("project check uses canonical root, saved options and ordered stages", async () => {
  mockCheck();
  const order: string[] = [];
  vi.mocked(api.inspectSourceProject).mockResolvedValue({
    ...context,
    lastOptions: {
      path: "/old",
      ...settings,
      extraIgnoredDirs: ["custom"],
      ignoreInvalidPolicy: false,
    },
  });
  vi.mocked(api.scanProject).mockImplementation(async (options) => {
    expect(options.path).toBe("/real/project");
    expect(options.extraIgnoredDirs).toEqual(["custom"]);
    order.push("source");
    return source;
  });
  vi.mocked(api.findLockfiles).mockImplementation(async (path) => {
    expect(path).toBe("/real/project");
    order.push("discovery");
    return [{ path: "lock", kind: "npm", packages: 1 }];
  });
  vi.mocked(api.scanDependencies).mockImplementation(async (path) => {
    expect(path).toBe("/real/project");
    order.push("dependencies");
    return dependencyResult();
  });
  await startProjectCheck("/alias", settings);
  expect(order).toEqual(["source", "discovery", "dependencies"]);
  expect(useScanWorkStore.getState().check?.status).toBe("completed");
  expect(useScanWorkStore.getState().active).toBeNull();
});
test("no lockfiles means not applicable and source errors retain failed outcome", async () => {
  mockCheck();
  vi.mocked(api.findLockfiles).mockResolvedValue([]);
  await startProjectCheck("/alias", settings);
  expect(useScanWorkStore.getState().check?.dependencies).toBe(
    "not applicable",
  );
  expect(api.scanDependencies).not.toHaveBeenCalled();
  vi.mocked(api.scanProject).mockRejectedValue(new Error("source unavailable"));
  await startProjectCheck("/alias", settings);
  expect(useScanWorkStore.getState().check?.status).toBe("failed");
  expect(useScanWorkStore.getState().check?.error).toContain(
    "source unavailable",
  );
});
test("cancellation during discovery blocks next stage and duplicate launch cannot replace ownership", async () => {
  mockCheck();
  let finish!: (v: never[]) => void;
  vi.mocked(api.findLockfiles).mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const pending = startProjectCheck("/alias", settings);
  await vi.waitFor(() =>
    expect(useScanWorkStore.getState().active?.stage).toBe("Finding lockfiles"),
  );
  await startProjectCheck("/other", settings);
  expect(useScanWorkStore.getState().check?.path).toBe("/real/project");
  await cancelActiveScan();
  finish([]);
  await pending;
  expect(useScanWorkStore.getState().check?.status).toBe("cancelled");
  expect(api.scanDependencies).not.toHaveBeenCalled();
});
test("scan ownership cannot be released by an older run", () => {
  const old = acquireScan("source", "/a", "Source scan")!;
  expect(acquireScan("dependencies", "/b", "Dependencies")).toBeNull();
  releaseScan(old);
  const current = acquireScan("dependencies", "/b", "Dependencies")!;
  releaseScan(old);
  expect(useScanWorkStore.getState().active?.id).toBe(current);
});
test("missing settings and incomplete source or unknown dependency coverage are never completed checks", async () => {
  mockCheck();
  await startProjectCheck("/a", null);
  expect(useScanWorkStore.getState().check?.error).toMatch(/Settings/);
  expect(api.scanProject).not.toHaveBeenCalled();
  vi.mocked(api.scanProject).mockResolvedValue({
    ...source,
    status: "incomplete",
  });
  await startProjectCheck("/a", settings);
  expect(useScanWorkStore.getState().check?.status).toBe("failed");
  expect(api.scanDependencies).not.toHaveBeenCalled();
  vi.mocked(api.scanProject).mockResolvedValue(source);
  vi.mocked(api.scanDependencies).mockResolvedValue({
    ...dependencyResult(),
    summary: { ...dependencyResult().summary, advisoryCoverage: "unknown" },
  });
  await startProjectCheck("/a", settings);
  expect(useScanWorkStore.getState().check?.status).toBe("incomplete");
});

test("a failed retry preserves last results without upgrading failed state to complete", async () => {
  mockCheck();
  await startProjectCheck("/real/project", settings);
  vi.mocked(api.scanProject).mockRejectedValue({
    code: "scanFailed",
    message: "disk unavailable",
    retryable: true,
  });
  await startProjectCheck("/real/project", settings);
  const check = useScanWorkStore.getState().check!;
  expect(check.status).toBe("failed");
  expect(check.sourceResult?.runId).toBe("s");
  expect(check.dependencyResult).toBeDefined();
  expect(check.error).toContain("disk unavailable");
});

test("dependency failure retains completed source evidence and usable settings are required", async () => {
  mockCheck();
  vi.mocked(api.scanDependencies).mockRejectedValue("OSV unavailable");
  await startProjectCheck("/real/project", settings);
  expect(useScanWorkStore.getState().check).toMatchObject({
    status: "failed",
    source: "completed",
    dependencies: "failed",
    error: "OSV unavailable",
  });
  vi.mocked(api.inspectSourceProject).mockResolvedValue({
    ...context,
    policy: { status: "invalid", message: "bad policy" },
  });
  await startProjectCheck("/real/project", settings);
  expect(useScanWorkStore.getState().check?.error).toMatch(/policy is invalid/);
});

test("retry-save reconciliation preserves failed outcomes and ignores other target/run identities", async () => {
  const { reconcileSourceRunSave } = await import("./coordinator");
  const saved = sourceResult("/a");
  const original = {
    path: "/a",
    status: "failed" as const,
    source: "completed, not saved",
    dependencies: "failed",
    error: "OSV unavailable",
    sourceResult: {
      ...saved,
      persistence: { status: "notSaved" as const, retryToken: "retry" },
    },
  };
  useScanWorkStore.setState({ check: original });
  reconcileSourceRunSave("/b", saved);
  expect(useScanWorkStore.getState().check).toBe(original);
  reconcileSourceRunSave("/a", { ...saved, runId: "other" });
  expect(useScanWorkStore.getState().check).toBe(original);
  reconcileSourceRunSave("/a", { ...saved, projectId: "/b" });
  expect(useScanWorkStore.getState().check).toBe(original);
  reconcileSourceRunSave("/a", saved);
  expect(useScanWorkStore.getState().check).toMatchObject({
    status: "failed",
    source: "completed",
    dependencies: "failed",
    error: "OSV unavailable",
    sourceResult: { persistence: { status: "saved" } },
  });
});

test("a save during dependency checking remains saved in the final project-check outcome", async () => {
  const { reconcileSourceRunSave } = await import("./coordinator");
  mockCheck();
  const saved = sourceResult("/real/project");
  vi.mocked(api.scanProject).mockResolvedValue({
    ...saved,
    persistence: { status: "notSaved", retryToken: "retry" },
  });
  let finish!: (value: ReturnType<typeof dependencyResult>) => void;
  vi.mocked(api.scanDependencies).mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const pending = startProjectCheck("/real/project", settings);
  await vi.waitFor(() =>
    expect(useScanWorkStore.getState().active?.stage).toBe(
      "Checking dependencies",
    ),
  );
  reconcileSourceRunSave("/real/project", saved);
  finish(dependencyResult());
  await pending;
  expect(useScanWorkStore.getState().check).toMatchObject({
    status: "completed",
    source: "completed",
    dependencies: "completed",
    sourceResult: { persistence: { status: "saved" } },
  });
});
