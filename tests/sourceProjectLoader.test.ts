import assert from "node:assert/strict";
import test from "node:test";
import { SourceProjectLoader } from "../src/features/source-scan/projectLoader";
import type {
  ProjectContext,
  ScanRunDetail,
  ScanRunSummary,
} from "../src/lib/types";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function context(id: string): ProjectContext {
  return {
    projectId: id,
    canonicalPath: `/${id}`,
    displayName: id,
    policy: { status: "missing" },
    lastCompletedRunId: `run-${id}`,
    lastOptions: null,
  };
}

function run(id: string): ScanRunDetail {
  return {
    projectId: id,
    runId: `run-${id}`,
    baselineRunId: null,
    status: "completed",
    persistence: { status: "saved" },
    policy: { status: "missing" },
    startedAt: "2026-08-21T00:00:00Z",
    completedAt: "2026-08-21T00:01:00Z",
    summary: {
      path: `/${id}`,
      filesScanned: 1,
      filesSkipped: 0,
      bytesScanned: 10,
      durationMs: 1000,
      secretsFound: 0,
      vulnerabilitiesFound: 0,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      rulesFired: {},
    },
    findings: [],
    maintenanceWarning: null,
  };
}

function summary(id: string): ScanRunSummary {
  return {
    runId: `run-${id}`,
    projectId: id,
    status: "completed",
    startedAt: "2026-08-21T00:00:00Z",
    completedAt: "2026-08-21T00:01:00Z",
    totalFindings: 0,
    newFindings: 0,
    resolvedFindings: 0,
  };
}

test("the latest target wins when project inspection resolves out of order", async () => {
  const inspections = new Map<string, ReturnType<typeof deferred<ProjectContext>>>();
  inspections.set("/project-a", deferred<ProjectContext>());
  inspections.set("/project-b", deferred<ProjectContext>());

  const loader = new SourceProjectLoader({
    inspectSourceProject: (path) => inspections.get(path)!.promise,
    listSourceRuns: async (projectId) => [summary(projectId)],
    loadSourceRun: async (runId) => run(runId.replace(/^run-/, "")),
  });

  const loadA = loader.load("/project-a");
  const loadB = loader.load("/project-b");
  inspections.get("/project-b")!.resolve(context("project-b"));
  const resultB = await loadB;
  inspections.get("/project-a")!.resolve(context("project-a"));
  const resultA = await loadA;

  assert.equal(resultA, null);
  assert.equal(resultB?.context.projectId, "project-b");
  assert.equal(resultB?.run?.runId, "run-project-b");
});

test("a project without a prior run still loads its durable context", async () => {
  const loader = new SourceProjectLoader({
    inspectSourceProject: async () => ({
      ...context("new-project"),
      lastCompletedRunId: null,
      policy: { status: "invalid", message: "reason is required" },
    }),
    listSourceRuns: async () => [],
    loadSourceRun: async () => {
      throw new Error("must not be called");
    },
  });

  const loaded = await loader.load("/new-project");
  assert.equal(loaded?.run, null);
  assert.deepEqual(loaded?.runs, []);
  assert.equal(loaded?.context.policy.status, "invalid");
});

test("invalidate prevents an in-flight load from publishing", async () => {
  const inspection = deferred<ProjectContext>();
  const loader = new SourceProjectLoader({
    inspectSourceProject: () => inspection.promise,
    listSourceRuns: async () => [],
    loadSourceRun: async () => run("unused"),
  });
  const pending = loader.load("/project");
  loader.invalidate();
  inspection.resolve(context("project"));
  assert.equal(await pending, null);
});
