import assert from "node:assert/strict";
import test from "node:test";
import { latestCompletedRun, normalizedTarget } from "../src/lib/durableRuns";
import type { CanonicalRun } from "../src/lib/types";

function run(overrides: Partial<CanonicalRun>): CanonicalRun {
  return {
    id: "run-1",
    kind: "dependencies",
    targetLabel: "/project",
    state: "completed",
    attempt: 1,
    createdAtMs: 1,
    updatedAtMs: 2,
    engineIds: [],
    rulePackIds: [],
    providerSnapshotIds: [],
    warnings: [],
    ...overrides,
  };
}

test("normalizes path separators and trailing separators", () => {
  assert.equal(normalizedTarget("C:\\work\\project\\"), "C:/work/project");
});

test("selects only the newest completed run for the same target and family", () => {
  const selected = latestCompletedRun(
    [
      run({ id: "failed", state: "failed", updatedAtMs: 20 }),
      run({ id: "binary", kind: "binary", updatedAtMs: 30 }),
      run({ id: "other", targetLabel: "/other", updatedAtMs: 40 }),
      run({ id: "older", updatedAtMs: 4 }),
      run({ id: "newer", updatedAtMs: 8 }),
    ],
    "dependencies",
    "/project/",
  );
  assert.equal(selected?.id, "newer");
});
