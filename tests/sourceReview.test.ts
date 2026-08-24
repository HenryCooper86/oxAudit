import assert from "node:assert/strict";
import test from "node:test";
import {
  ALL_GATES,
  buildReviewRequest,
  createReviewDraft,
  updateGate,
  validateReviewDraft,
} from "../src/features/source-scan/reviewModel";
import type { Finding } from "../src/lib/types";

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

test("confirmed vulnerabilities require all five surviving gates with evidence", () => {
  const target = finding();
  let draft = { ...createReviewDraft(target), state: "confirmed" as const, reason: "Verified exploit path" };
  assert.equal(validateReviewDraft(target, draft).valid, false);

  for (const gate of ALL_GATES) {
    draft = updateGate(draft, gate, {
      verdict: "survives",
      evidence: `Verified ${gate} at src/app.ts:12`,
    });
  }
  assert.equal(validateReviewDraft(target, draft).valid, true);
});

test("false positives require exactly one supported eliminating gate", () => {
  const target = finding();
  let draft = {
    ...createReviewDraft(target),
    state: "falsePositive" as const,
    reason: "Development-only path",
    decidingGate: "reachable" as const,
  };
  draft = updateGate(draft, "reachable", {
    verdict: "eliminates",
    evidence: "Excluded from production build",
  });
  assert.equal(validateReviewDraft(target, draft).valid, true);

  draft = updateGate(draft, "intended", {
    verdict: "eliminates",
    evidence: "Designed behavior",
  });
  assert.equal(validateReviewDraft(target, draft).valid, false);
});

test("accepted risk and suppression require a reason and a future expiry when present", () => {
  const target = finding();
  const draft = { ...createReviewDraft(target), state: "acceptedRisk" as const };
  assert.equal(validateReviewDraft(target, draft).fieldErrors.reason !== undefined, true);
  assert.equal(
    validateReviewDraft(target, { ...draft, reason: "Temporary exception", expiresAt: "2020-01-01" }).fieldErrors.expiresAt !== undefined,
    true,
  );

  const futureDraft = {
    ...draft,
    reason: "Temporary exception",
    expiresAt: "2100-09-21T12:00",
  };
  assert.equal(validateReviewDraft(target, futureDraft).valid, true);
  const request = buildReviewRequest("project-1", target, futureDraft);
  assert.equal(Date.parse(request.expiresAt ?? ""), Date.parse(futureDraft.expiresAt));
});

test("confirmed reviews cannot be written to project policy", () => {
  const target = finding();
  let draft = {
    ...createReviewDraft(target),
    state: "confirmed" as const,
    reason: "Confirmed",
    origin: "projectPolicy" as const,
  };
  for (const gate of ALL_GATES) {
    draft = updateGate(draft, gate, { verdict: "survives", evidence: "Verified" });
  }
  assert.equal(validateReviewDraft(target, draft).fieldErrors.origin !== undefined, true);
});

test("secret requests never include detected credential material", () => {
  const secretFinding = finding({
    category: "secret",
    matchText: "oxaudit-secret-canary",
    context: "token=oxaudit-secret-canary",
  });
  const request = buildReviewRequest("project-1", secretFinding, {
    ...createReviewDraft(secretFinding),
    state: "falsePositive",
    reason: "Synthetic test token",
  });
  assert.equal(JSON.stringify(request).includes("oxaudit-secret-canary"), false);
  assert.equal(request.evidence, null);
  assert.deepEqual(request.gates, []);
});

test("candidate requests clear all review fields", () => {
  const target = finding();
  const request = buildReviewRequest("project-1", target, {
    ...createReviewDraft(target),
    reason: "stale",
    evidence: "stale",
    entryPoint: "stale",
    dataFlow: "stale",
    expiresAt: "2030-01-01",
  });
  assert.equal(request.reason, "");
  assert.equal(request.evidence, null);
  assert.deepEqual(request.gates, []);
  assert.equal(request.expiresAt, null);
});

test("an unreviewed finding starts from what the analysis worked out", () => {
  // The gate model treats a finding as a candidate until something tries to
  // disprove it. The analysis already made that attempt, so a reviewer should
  // edit its argument rather than retype one.
  const draft = createReviewDraft({
    ...finding(),
    review: null,
    analysisGates: [
      {
        gate: "attackerControlled",
        verdict: "survives",
        evidence: "The value traces to a parameter.",
      },
    ],
  });

  const gate = draft.gates.find((note) => note.gate === "attackerControlled");
  assert.equal(gate?.verdict, "survives");
  assert.match(gate?.evidence ?? "", /traces to a parameter/);

  // Gates the analysis said nothing about stay unanswered rather than being
  // guessed at.
  assert.equal(draft.gates.find((note) => note.gate === "intended")?.verdict, "unknown");
});

test("a recorded human decision is never overwritten by a suggestion", () => {
  const draft = createReviewDraft({
    ...finding(),
    review: {
      id: "r1",
      projectId: "p1",
      fingerprintVersion: 1,
      fingerprint: "fp",
      state: "confirmed",
      reason: "Reviewed by hand.",
      evidence: null,
      entryPoint: null,
      dataFlow: null,
      gates: [
        {
          gate: "attackerControlled",
          verdict: "eliminates",
          evidence: "Callers are internal only.",
        },
      ],
      decidingGate: null,
      expiresAt: null,
      origin: "local",
      updatedAt: "2026-01-01T00:00:00Z",
      supersededAt: null,
    },
    analysisGates: [
      {
        gate: "attackerControlled",
        verdict: "survives",
        evidence: "The value traces to a parameter.",
      },
    ],
  } as never);

  const gate = draft.gates.find((note) => note.gate === "attackerControlled");
  // The person looked and disagreed with the machine. Their answer stands.
  assert.equal(gate?.verdict, "eliminates");
  assert.match(gate?.evidence ?? "", /internal only/);
});

test("a finding with no analysis gates behaves as before", () => {
  const draft = createReviewDraft({ ...finding(), review: null, analysisGates: [] });
  assert.ok(draft.gates.every((note) => note.verdict === "unknown"));
});
