import { describe, expect, test } from "vitest";

import {
  BULK_STATES,
  EMPTY_SELECTION,
  buildBulkRequests,
  describeBulkAction,
  pruneToVisible,
  selectAll,
  selectRange,
  toggle,
  validateBulkDraft,
  type BulkDraft,
} from "./selectionModel";
import type { Finding } from "../../lib/types";

function finding(fingerprint: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id: fingerprint,
    category: "vulnerability",
    ruleId: "js-eval",
    ruleName: "eval() usage",
    severity: "high",
    title: "eval() usage",
    description: "",
    filePath: `src/${fingerprint}.js`,
    line: 1,
    column: 1,
    matchText: "eval(",
    context: "",
    language: "javascript",
    cwe: "CWE-95",
    cweExploited: false,
    cweExploitedCount: 0,
    recommendation: "",
    entropy: null,
    verified: null,
    analysis: "syntax",
    observationRunId: "run-1",
    resolvedByRunId: null,
    fingerprintVersion: 1,
    fingerprint,
    scope: null,
    scopeReason: null,
    review: null,
    reviewHistory: [],
    diffStatus: null,
    ...overrides,
  } as Finding;
}

const visible = ["a", "b", "c", "d"].map((id) => finding(id));

const draft = (overrides: Partial<BulkDraft> = {}): BulkDraft => ({
  state: "acceptedRisk",
  reason: "Reviewed as a class; tracked in SEC-441.",
  expiresAt: "",
  ...overrides,
});

describe("selection", () => {
  test("toggling adds then removes", () => {
    const once = toggle(EMPTY_SELECTION, "a");
    expect([...once]).toEqual(["a"]);
    expect([...toggle(once, "a")]).toEqual([]);
  });

  test("toggling does not mutate the previous selection", () => {
    // React state must not be edited in place, or the list stops re-rendering.
    const first = toggle(EMPTY_SELECTION, "a");
    toggle(first, "b");
    expect([...first]).toEqual(["a"]);
  });

  test("select all covers exactly what is on screen", () => {
    // Scoped to the filtered view on purpose: the filters are how a reviewer
    // says "this class", and reaching past them would act on findings nobody
    // has looked at.
    expect([...selectAll(visible)].sort()).toEqual(["a", "b", "c", "d"]);
  });

  test("a range covers both ends regardless of direction", () => {
    expect([...selectRange(EMPTY_SELECTION, visible, "b", "d")].sort()).toEqual(["b", "c", "d"]);
    expect([...selectRange(EMPTY_SELECTION, visible, "d", "b")].sort()).toEqual(["b", "c", "d"]);
  });

  test("a range keeps what was already selected", () => {
    const existing = toggle(EMPTY_SELECTION, "a");
    expect([...selectRange(existing, visible, "c", "d")].sort()).toEqual(["a", "c", "d"]);
  });

  test("a range against a finding that is not on screen changes nothing", () => {
    const existing = toggle(EMPTY_SELECTION, "a");
    expect(selectRange(existing, visible, "a", "gone")).toBe(existing);
  });

  test("pruning drops findings the filters removed", () => {
    // The bug this prevents: filter to secrets, select forty, filter to
    // something else, and apply a decision to findings no longer on screen.
    const selection = selectAll(visible);
    const narrowed = pruneToVisible(selection, [visible[0], visible[2]]);
    expect([...narrowed].sort()).toEqual(["a", "c"]);
  });

  test("pruning to an empty view clears the selection", () => {
    expect([...pruneToVisible(selectAll(visible), [])]).toEqual([]);
  });
});

describe("validateBulkDraft", () => {
  test("refuses a decision with nothing selected", () => {
    const result = validateBulkDraft(EMPTY_SELECTION, draft());
    expect(result.valid).toBe(false);
    expect(result.problems.join(" ")).toMatch(/select at least one/i);
  });

  test("refuses a dismissal with no reason", () => {
    const result = validateBulkDraft(selectAll(visible), draft({ reason: "  " }));
    expect(result.valid).toBe(false);
    expect(result.problems.join(" ")).toMatch(/reason/i);
  });

  test("allows resetting to candidate without a reason", () => {
    // Clearing a decision is not itself a decision that needs justifying.
    expect(validateBulkDraft(selectAll(visible), draft({ state: "candidate", reason: "" })).valid).toBe(
      true,
    );
  });

  test("refuses an expiry in the past", () => {
    const result = validateBulkDraft(selectAll(visible), draft({ expiresAt: "2020-01-01T00:00" }));
    expect(result.valid).toBe(false);
    expect(result.problems.join(" ")).toMatch(/future/i);
  });

  test("refuses an unparseable expiry", () => {
    const result = validateBulkDraft(selectAll(visible), draft({ expiresAt: "soon" }));
    expect(result.valid).toBe(false);
  });

  test("accepts an empty expiry", () => {
    expect(validateBulkDraft(selectAll(visible), draft({ expiresAt: "" })).valid).toBe(true);
  });

  test("does not offer verdicts that need per-finding evidence", () => {
    // Confirming a vulnerability, or naming the gate that eliminates it,
    // requires evidence that cannot be true of forty findings at once.
    const offered = BULK_STATES.map((entry) => entry.value);
    expect(offered).not.toContain("confirmed");
    expect(offered).not.toContain("falsePositive");
  });
});

describe("buildBulkRequests", () => {
  test("produces one request per selected finding", () => {
    const selection = selectRange(EMPTY_SELECTION, visible, "a", "c");
    const requests = buildBulkRequests("project-1", visible, selection, draft());
    expect(requests).toHaveLength(3);
    expect(requests.map((request) => request.fingerprint).sort()).toEqual(["a", "b", "c"]);
  });

  test("carries each finding's own identity rather than a shared one", () => {
    // A bulk action is a convenience for the reviewer, not a different kind of
    // record. Each entry has to stand on its own in the history.
    const mixed = [finding("a", { category: "secret", fingerprintVersion: 2 }), finding("b")];
    const requests = buildBulkRequests("project-1", mixed, selectAll(mixed), draft());
    expect(requests.find((request) => request.fingerprint === "a")?.category).toBe("secret");
    expect(requests.find((request) => request.fingerprint === "a")?.fingerprintVersion).toBe(2);
    expect(requests.find((request) => request.fingerprint === "b")?.category).toBe("vulnerability");
  });

  test("never builds a request for a finding that is not on screen", () => {
    const selection = new Set(["a", "not-visible"]);
    const requests = buildBulkRequests("project-1", visible, selection, draft());
    expect(requests.map((request) => request.fingerprint)).toEqual(["a"]);
  });

  test("trims the reason and normalises an empty expiry to null", () => {
    const requests = buildBulkRequests(
      "project-1",
      visible,
      toggle(EMPTY_SELECTION, "a"),
      draft({ reason: "  spaced  ", expiresAt: "   " }),
    );
    expect(requests[0].reason).toBe("spaced");
    expect(requests[0].expiresAt).toBeNull();
  });

  test("records the decision as local rather than as project policy", () => {
    // Writing to the committed policy is a separate, deliberate act; a bulk
    // triage pass must not silently change what the repository asserts.
    const requests = buildBulkRequests("project-1", visible, selectAll(visible), draft());
    expect(requests.every((request) => request.origin === "local")).toBe(true);
  });
});

describe("describeBulkAction", () => {
  test("names the decision and the count", () => {
    // "Apply" without a blast radius is a button people press by accident.
    expect(describeBulkAction(selectAll(visible), draft())).toBe("Accepted risk · 4 findings");
  });

  test("uses the singular for one finding", () => {
    expect(describeBulkAction(toggle(EMPTY_SELECTION, "a"), draft())).toBe(
      "Accepted risk · 1 finding",
    );
  });
});
