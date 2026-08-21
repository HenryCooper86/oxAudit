import assert from "node:assert/strict";
import test from "node:test";
import {
  countViews,
  filterFindings,
  findingView,
  nextSelection,
  sanitizeExport,
} from "../src/features/source-scan/resultsModel";
import type { ResultsQuery } from "../src/features/source-scan/types";
import type { Finding, ReviewRecord } from "../src/lib/types";

function review(state: ReviewRecord["state"]): ReviewRecord {
  return {
    id: `review-${state}`,
    projectId: "project-1",
    fingerprintVersion: 1,
    fingerprint: `fingerprint-${state}`,
    state,
    reason: "Reviewed",
    evidence: null,
    entryPoint: null,
    dataFlow: null,
    gates: [],
    decidingGate: null,
    expiresAt: null,
    origin: "local",
    policyHash: null,
    updatedAt: "2026-08-21T00:00:00Z",
    supersededAt: null,
  };
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "observation-1",
    category: "vulnerability",
    ruleId: "rule-1",
    ruleName: "Unsafe call",
    severity: "high",
    title: "Unsafe call",
    description: "Unsafe call detected",
    filePath: "src/app.ts",
    line: 12,
    column: 4,
    matchText: "danger(input)",
    context: "danger(input)",
    language: "TypeScript",
    cwe: "CWE-78",
    cweExploited: false,
    cweExploitedCount: 0,
    recommendation: "Use a safe API",
    entropy: null,
    verified: null,
    observationRunId: "run-1",
    resolvedByRunId: null,
    fingerprintVersion: 1,
    fingerprint: "fingerprint-1",
    scope: "production",
    scopeReason: "source directory",
    review: null,
    reviewHistory: [],
    diffStatus: "new",
    ...overrides,
  };
}

const baseQuery: ResultsQuery = {
  view: "open",
  category: "all",
  severity: "all",
  scope: "all",
  language: "all",
  search: "",
};

test("every candidate belongs to exactly one durable view", () => {
  const findings = [
    finding({ fingerprint: "prod", scope: "production", review: null }),
    finding({ fingerprint: "fixture", scope: "fixture", review: null }),
    finding({ fingerprint: "unknown", scope: null, review: null }),
    finding({ fingerprint: "confirmed", scope: "test", review: review("confirmed") }),
    finding({ fingerprint: "closed", review: review("acceptedRisk") }),
    finding({ fingerprint: "false", review: review("falsePositive") }),
    finding({ fingerprint: "suppressed", review: review("suppressed") }),
    finding({ fingerprint: "resolved", diffStatus: "resolved", review: null }),
  ];

  assert.deepEqual(findings.map(findingView), [
    "open",
    "otherScopes",
    "open",
    "open",
    "closed",
    "closed",
    "closed",
    "resolved",
  ]);
  assert.equal(Object.values(countViews(findings)).reduce((sum, count) => sum + count, 0), findings.length);
});

test("filters apply after durable view membership without mutating input", () => {
  const findings = [
    finding({ fingerprint: "a", category: "secret", severity: "critical", language: "Rust", ruleName: "Token", matchText: "[REDACTED]" }),
    finding({ fingerprint: "b", category: "vulnerability", severity: "high", language: "TypeScript", filePath: "src/server.ts" }),
    finding({ fingerprint: "c", scope: "fixture", language: "TypeScript" }),
  ];
  const snapshot = structuredClone(findings);

  assert.deepEqual(
    filterFindings(findings, {
      ...baseQuery,
      category: "vulnerability",
      severity: "high",
      scope: "production",
      language: "TypeScript",
      search: "server",
    }).map((item) => item.fingerprint),
    ["b"],
  );
  assert.deepEqual(findings, snapshot);
});

test("selection stays stable when visible and falls back deterministically", () => {
  const findings = [finding({ fingerprint: "a" }), finding({ fingerprint: "b" })];
  assert.equal(nextSelection(findings, "b"), "b");
  assert.equal(nextSelection(findings, "missing"), "a");
  assert.equal(nextSelection([], "a"), null);
});

test("exports redact secret evidence and allowlist fields", () => {
  const secret = finding({
    category: "secret",
    fingerprint: "secret",
    matchText: "oxaudit-secret-canary",
    context: "token=oxaudit-secret-canary",
  });
  const exported = sanitizeExport([secret]);
  const serialized = JSON.stringify(exported);
  assert.equal(serialized.includes("oxaudit-secret-canary"), false);
  assert.equal(exported[0]?.matchText, "[REDACTED]");
  assert.equal(exported[0]?.context, "[REDACTED]");
  assert.equal("reviewHistory" in (exported[0] ?? {}), false);
});
