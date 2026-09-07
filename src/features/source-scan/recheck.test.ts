import { expect, test } from "vitest";
import { sourceResult } from "../../../tests/fixtures/projectHome";
import type { Finding } from "../../lib/types";
import { assessRecheck } from "./recheck";
const finding = { fingerprint: "fp", fingerprintVersion: 1, category: "vulnerability", ruleId: "js-eval", filePath: "app.js", line: 3, observationRunId: "s" } as Finding;
const original = { ...sourceResult(), findings: [finding] };
const current = { ...sourceResult(), runId: "next" };
test("recheck distinguishes still detected, covered absence and nearby changed identity", () => {
  expect(assessRecheck(original, finding, current, [{ ...finding, observationRunId: "next", diffStatus: "unchanged" }]).status).toBe("present");
  const absent = { ...finding, diffStatus: "resolved", resolvedByRunId: "next" } as Finding;
  expect(assessRecheck(original, finding, current, [absent]).status).toBe("absent");
  expect(assessRecheck(original, finding, current, [absent, { ...finding, fingerprint: "shifted", line: 5, observationRunId: "next" }]).status).toBe("changed");
});
test("missing skipped or unsupported coverage cannot resolve a finding", () => {
  for (const comparison of [[], [{ ...finding, diffStatus: "notEvaluated" } as Finding]]) {
    expect(assessRecheck(original, finding, current, comparison).status).toBe("notEvaluated");
  }
});
test("wrong project, unsaved, cancelled or incomplete evidence cannot resolve", () => {
  const absent = [{ ...finding, diffStatus: "resolved", resolvedByRunId: "next" } as Finding];
  for (const run of [{ ...current, projectId: "other" }, { ...current, status: "incomplete" as const }, { ...current, persistence: { status: "notSaved", retryToken: "retry" } as const }]) {
    expect(() => assessRecheck(original, finding, run, absent)).toThrow();
  }
});
