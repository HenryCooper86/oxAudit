import { render, screen } from "@testing-library/react";
import { describe, expect, test, vi } from "vitest";

import { FindingDetail } from "./FindingDetail";
import type { Finding } from "../lib/types";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-1",
    category: "vulnerability",
    ruleId: "js-eval",
    ruleName: "eval() usage",
    severity: "high",
    title: "eval() usage",
    description: "eval() executes arbitrary strings as code.",
    filePath: "src/render.js",
    line: 12,
    column: 10,
    matchText: "eval(userInput)",
    context: "return eval(userInput);",
    language: "javascript",
    cwe: "CWE-95",
    cweExploited: false,
    cweExploitedCount: 0,
    recommendation: "Remove the eval() call.",
    entropy: null,
    verified: null,
    analysis: "syntax",
    analysisGates: [],
    observationRunId: "run-1",
    resolvedByRunId: null,
    fingerprintVersion: 1,
    fingerprint: "fp-1",
    scope: null,
    scopeReason: null,
    review: null,
    reviewHistory: [],
    diffStatus: null,
    ...overrides,
  };
}

function renderFinding(overrides: Partial<Finding> = {}) {
  render(
    <FindingDetail
      projectId="project-1"
      finding={finding(overrides)}
      savingReview={false}
      reviewError={null}
      onSaveReview={vi.fn().mockResolvedValue(undefined)}
      onCopy={vi.fn()}
      onOpenFile={vi.fn()}
    />,
  );
}

describe("FindingDetail analysis evidence", () => {
  test("explains that a syntax-qualified match is parsed code without claiming exploitability", () => {
    renderFinding({ analysis: "syntax" });

    const evidence = screen.getByRole("region", { name: "Analysis evidence" });
    expect(evidence).toHaveTextContent(/match is in parsed code/i);
    expect(evidence).toHaveTextContent(/does not prove exploitability/i);
  });

  test("explains that text-only matching did not verify syntax", () => {
    renderFinding({ analysis: "text" });

    const evidence = screen.getByRole("region", { name: "Analysis evidence" });
    expect(evidence).toHaveTextContent(/syntax was not verified/i);
  });

  test("does not claim a syntax-qualified secret was outside a string literal", () => {
    renderFinding({
      category: "secret",
      analysis: "syntax",
      matchText: "AKIAIOSFODNN7EXAMPLE",
    });

    const evidence = screen.getByRole("region", { name: "Analysis evidence" });
    expect(evidence).toHaveTextContent(/parsed source was checked for comment-only matches/i);
    expect(evidence).not.toHaveTextContent(/not a comment or string literal/i);
  });

  test("keeps secret evidence redacted while showing the human review state", () => {
    renderFinding({
      category: "secret",
      matchText: "AKIAIOSFODNN7EXAMPLE",
      analysis: "text",
      review: {
        id: "review-1",
        projectId: "project-1",
        fingerprintVersion: 1,
        fingerprint: "fp-1",
        state: "acceptedRisk",
        reason: "Tracked under SEC-441.",
        evidence: null,
        origin: "local",
        updatedAt: "2026-09-07T00:00:00.000Z",
        expiresAt: null,
        supersededAt: null,
        entryPoint: null,
        dataFlow: null,
        gates: [],
        decidingGate: null,
        policyHash: null,
      },
    });

    expect(screen.getByText("[REDACTED]")).toBeInTheDocument();
    expect(screen.queryByText("AKIAIOSFODNN7EXAMPLE")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Current review" })).toBeInTheDocument();
    expect(screen.getAllByText("Accepted risk").length).toBeGreaterThan(0);
  });
});
