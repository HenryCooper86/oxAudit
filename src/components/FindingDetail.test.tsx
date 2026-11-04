import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

function workflowDetail(value: Finding, projectId = "project-1", onSaveReview = vi.fn().mockResolvedValue(undefined)) {
  return <FindingDetail projectId={projectId} finding={value} savingReview={false}
    reviewError={null} onSaveReview={onSaveReview} onCopy={vi.fn()} onOpenFile={vi.fn()} />;
}

function reviewedFinding(reason: string, id: string): Finding {
  return finding({ review: {
    id, projectId: "project-1", fingerprintVersion: 1, fingerprint: "fp-1",
    state: "acceptedRisk", reason, evidence: null, origin: "local",
    updatedAt: "2026-11-04T00:00:00Z", expiresAt: null, supersededAt: null,
    entryPoint: null, dataFlow: null, gates: [], decidingGate: null, policyHash: null,
  } });
}

describe("Review workflow", () => {
  test.each([
    { submitted: "Submitted reason", newer: "Original reason", label: "reverting to the old baseline" },
    { submitted: "Original reason", newer: "Newer reason", label: "submitting an unchanged review" },
  ])("a late acknowledgement preserves edits after $label", async ({ submitted, newer }) => {
    const user = userEvent.setup();
    const original = reviewedFinding("Original reason", "original");
    const { rerender } = render(workflowDetail(original));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    if (submitted !== "Original reason") {
      await user.clear(screen.getByLabelText("Reason"));
      await user.type(screen.getByLabelText("Reason"), submitted);
    }
    await user.click(screen.getByRole("button", { name: "Save review" }));
    rerender(<p>Another tool</p>);
    rerender(workflowDetail(original));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    await user.clear(screen.getByLabelText("Reason"));
    await user.type(screen.getByLabelText("Reason"), newer);
    rerender(workflowDetail(reviewedFinding(submitted, "acknowledged")));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    expect(screen.getByLabelText("Reason")).toHaveValue(newer);
    expect(screen.getByText("Unsaved review draft")).toBeInTheDocument();
  });

  test("unchanged save acknowledgements clear the unsaved indicator without losing later work", async () => {
    const user = userEvent.setup();
    const { rerender } = render(workflowDetail(finding()));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    await user.selectOptions(screen.getByLabelText("Decision"), "acceptedRisk");
    await user.type(screen.getByLabelText("Reason"), "Submitted reason");
    await user.click(screen.getByRole("button", { name: "Save review" }));
    rerender(workflowDetail(reviewedFinding("Submitted reason", "ack-one")));
    expect(screen.queryByText("Unsaved review draft")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    await user.type(screen.getByLabelText("Reason"), " with newer work");
    rerender(workflowDetail(reviewedFinding("Submitted reason", "ack-two")));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    expect(screen.getByLabelText("Reason")).toHaveValue("Submitted reason with newer work");
  });
  test("reveals the review editor inside the workspace and restores focus on cancel", async () => {
    const user = userEvent.setup();
    render(<main>{workflowDetail(finding())}</main>);
    const workspace = document.querySelector("main")!;
    vi.spyOn(workspace, "getBoundingClientRect").mockReturnValue(new DOMRect(0, 0, 900, 700));
    const bounds = HTMLElement.prototype.getBoundingClientRect;
    vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
      return this.tagName === "FORM" ? new DOMRect(0, 1000, 600, 900) : bounds.call(this);
    });
    const trigger = screen.getByRole("button", { name: "Review finding" });
    await user.click(trigger);
    expect(screen.getByRole("heading", { name: "Review decision" })).toHaveFocus();
    await waitFor(() => expect(workspace.scrollTop).toBe(1000));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(trigger).toHaveFocus();
  });

  test("restores a draft after switching findings and after leaving the page", async () => {
    const user = userEvent.setup();
    const first = finding(), other = finding({ fingerprint: "fp-other" });
    const { rerender } = render(workflowDetail(first));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    await user.selectOptions(screen.getByLabelText("Decision"), "acceptedRisk");
    await user.type(screen.getByLabelText("Reason"), "Waiting for owner approval");
    rerender(workflowDetail(other));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    expect(screen.getByLabelText("Decision")).toHaveValue("candidate");
    rerender(workflowDetail(first));
    expect(screen.getByText("Unsaved review draft")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    expect(screen.getByLabelText("Reason")).toHaveValue("Waiting for owner approval");
    rerender(<p>Another tool</p>);
    rerender(workflowDetail(first));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    expect(screen.getByLabelText("Reason")).toHaveValue("Waiting for owner approval");
    await user.click(screen.getByRole("button", { name: "Discard draft" }));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    expect(screen.getByLabelText("Decision")).toHaveValue("candidate");
    expect(screen.queryByText("Unsaved review draft")).not.toBeInTheDocument();
  });

  test("isolates drafts by project and fingerprint version", async () => {
    const user = userEvent.setup();
    const value = finding();
    const { rerender } = render(workflowDetail(value));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    await user.selectOptions(screen.getByLabelText("Decision"), "acceptedRisk");
    await user.type(screen.getByLabelText("Reason"), "Only project one");
    rerender(workflowDetail(value, "project-2"));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    expect(screen.getByLabelText("Decision")).toHaveValue("candidate");
    rerender(workflowDetail(finding({ fingerprintVersion: 2 })));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    expect(screen.getByLabelText("Decision")).toHaveValue("candidate");
    rerender(workflowDetail(value));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    expect(screen.getByLabelText("Reason")).toHaveValue("Only project one");
  });

  test("a new saved review invalidates the old draft instead of restoring stale edits", async () => {
    const user = userEvent.setup();
    const value = finding();
    const { rerender } = render(workflowDetail(value));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    await user.selectOptions(screen.getByLabelText("Decision"), "acceptedRisk");
    await user.type(screen.getByLabelText("Reason"), "Old draft");
    const reviewed = finding({ review: {
      id: "review-new", projectId: "project-1", fingerprintVersion: 1, fingerprint: "fp-1",
      state: "acceptedRisk", reason: "Saved by reviewer", evidence: null, origin: "local",
      updatedAt: "2026-11-04T00:00:00Z", expiresAt: null, supersededAt: null,
      entryPoint: null, dataFlow: null, gates: [], decidingGate: null, policyHash: null,
    } });
    rerender(workflowDetail(reviewed));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    expect(screen.getByLabelText("Reason")).toHaveValue("Saved by reviewer");
    expect(screen.queryByText("Unsaved review draft")).not.toBeInTheDocument();
  });

  test("a late failed save does not clear a newer draft", async () => {
    const user = userEvent.setup();
    let finish!: () => void;
    const save = vi.fn(() => new Promise<void>(resolve => { finish = resolve; }));
    const value = finding();
    const { rerender } = render(workflowDetail(value, "project-1", save));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    await user.selectOptions(screen.getByLabelText("Decision"), "acceptedRisk");
    await user.type(screen.getByLabelText("Reason"), "First draft");
    await user.click(screen.getByRole("button", { name: "Save review" }));
    // The parent reports failures in its error prop; its Promise<void> still resolves.
    rerender(<p>Another tool</p>);
    rerender(workflowDetail(value));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    await user.clear(screen.getByLabelText("Reason"));
    await user.type(screen.getByLabelText("Reason"), "Newer draft");
    finish();
    rerender(<p>Another tool</p>);
    rerender(workflowDetail(value));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    expect(screen.getByLabelText("Reason")).toHaveValue("Newer draft");
  });

  test("a late saved decision keeps edits made after that submission", async () => {
    const user = userEvent.setup();
    const value = finding();
    const { rerender } = render(workflowDetail(value));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    await user.selectOptions(screen.getByLabelText("Decision"), "acceptedRisk");
    await user.type(screen.getByLabelText("Reason"), "Submitted reason");
    await user.click(screen.getByRole("button", { name: "Save review" }));
    rerender(<p>Another tool</p>);
    rerender(workflowDetail(value));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    await user.clear(screen.getByLabelText("Reason"));
    await user.type(screen.getByLabelText("Reason"), "Newer unsaved reason");
    rerender(workflowDetail(finding({ review: {
      id: "review-late", projectId: "project-1", fingerprintVersion: 1, fingerprint: "fp-1",
      state: "acceptedRisk", reason: "Submitted reason", evidence: null, origin: "local",
      updatedAt: "2026-11-04T00:00:00Z", expiresAt: null, supersededAt: null,
      entryPoint: null, dataFlow: null, gates: [], decidingGate: null, policyHash: null,
    } })));
    await user.click(screen.getByRole("button", { name: "Review finding" }));
    expect(screen.getByLabelText("Reason")).toHaveValue("Newer unsaved reason");
    expect(screen.getByText("Unsaved review draft")).toBeInTheDocument();
  });
});

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

describe("FindingDetail recheck affordance", () => {
  test("states why recheck is disabled instead of failing silently", () => {
    render(
      <FindingDetail
        projectId="project-1"
        finding={finding()}
        savingReview={false}
        reviewError={null}
        onSaveReview={vi.fn().mockResolvedValue(undefined)}
        onCopy={vi.fn()}
        onOpenFile={vi.fn()}
        onRecheck={vi.fn()}
        recheckDisabled
        recheckDisabledReason="A scan is already running"
      />,
    );
    expect(screen.getByRole("button", { name: "Recheck finding" })).toBeDisabled();
    expect(screen.getByText("A scan is already running")).toBeInTheDocument();
  });

  test("renders no reason text when the control carries none", () => {
    render(
      <FindingDetail
        projectId="project-1"
        finding={finding()}
        savingReview={false}
        reviewError={null}
        onSaveReview={vi.fn().mockResolvedValue(undefined)}
        onCopy={vi.fn()}
        onOpenFile={vi.fn()}
        onRecheck={vi.fn()}
        recheckDisabled
      />,
    );
    expect(screen.getByRole("button", { name: "Recheck finding" })).toBeDisabled();
    expect(screen.queryByText("A scan is already running")).not.toBeInTheDocument();
  });
});
