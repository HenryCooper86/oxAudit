import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, test, vi } from "vitest";

import { FindingReviewForm } from "./FindingReviewForm";
import type { Finding } from "../../lib/types";

/**
 * A review is an append-only, durable security decision: "this is a real
 * vulnerability" or "this is not". Getting it wrong is not a UI defect, it is a
 * wrong record in an audit trail.
 *
 * The properties covered here are the ones a person is relying on when they
 * click Save:
 *
 *   - an incomplete decision cannot be submitted
 *   - the reason they typed is the reason that gets recorded
 *   - the form asks the falsification questions before accepting a verdict
 *   - nothing is submitted twice, and nothing is submitted on cancel
 */

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
    matchText: "eval(",
    context: "return eval(userInput);",
    language: "javascript",
    cwe: "CWE-95",
    cweExploited: false,
    cweExploitedCount: 0,
    recommendation: "Remove the eval() call.",
    entropy: null,
    verified: null,
    analysis: "syntax",
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
  } as Finding;
}

function setup(overrides: Partial<Finding> = {}) {
  const onSubmit = vi.fn().mockResolvedValue(undefined);
  const onCancel = vi.fn();
  const user = userEvent.setup();
  render(
    <FindingReviewForm
      projectId="project-1"
      finding={finding(overrides)}
      saving={false}
      error={null}
      onSubmit={onSubmit}
      onCancel={onCancel}
    />,
  );
  return { onSubmit, onCancel, user };
}

describe("FindingReviewForm", () => {
  test("is labelled so it is findable by assistive technology", () => {
    setup();
    expect(screen.getByRole("form", { name: "Review finding" })).toBeInTheDocument();
  });

  test("states plainly that an AI suggestion cannot submit the decision", () => {
    setup();
    // The product's position is that a human records the verdict. Saying so at
    // the point of decision is part of that, not decoration.
    expect(screen.getByText(/AI suggestions never submit this form/i)).toBeInTheDocument();
  });

  test("asks for no justification while the finding is still undecided", async () => {
    const { user } = setup();
    // `candidate` means "not yet reviewed". Demanding a reason to record that
    // nothing has been decided would make the default state unusable.
    expect(screen.queryByRole("textbox", { name: /reason/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^save/i }));
  });

  test("will not record a verdict with no reason given", async () => {
    const { onSubmit, user } = setup();

    await user.selectOptions(screen.getByRole("combobox", { name: /decision/i }), "falsePositive");
    await user.click(screen.getByRole("button", { name: /^save/i }));

    // A durable record with an empty justification is worse than no record:
    // it looks reviewed.
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByText(/Explain why this decision is appropriate/i)).toBeInTheDocument();
  });

  test("dismissing a vulnerability requires naming the gate that eliminates it", async () => {
    const { onSubmit, user } = setup();

    await user.selectOptions(screen.getByRole("combobox", { name: /decision/i }), "falsePositive");
    await user.type(
      await screen.findByRole("textbox", { name: /reason/i }),
      "Template input is a static allow-list.",
    );
    await user.click(screen.getByRole("button", { name: /^save/i }));

    // "It's a false positive" is an assertion; naming the gate that eliminates
    // it is an argument. The form will not record the first without the second.
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByText(/single gate that eliminates this finding/i)).toBeInTheDocument();
  });

  test("naming the deciding gate is not enough without evidence that it eliminates", async () => {
    const { onSubmit, user } = setup();

    await user.selectOptions(screen.getByRole("combobox", { name: /decision/i }), "falsePositive");
    await user.type(
      await screen.findByRole("textbox", { name: /reason/i }),
      "Template input is a static allow-list.",
    );
    await user.selectOptions(
      screen.getByRole("combobox", { name: /deciding gate/i }),
      "attackerControlled",
    );
    await user.click(screen.getByRole("button", { name: /^save/i }));

    // Picking a gate from a dropdown is still an assertion. The gate itself has
    // to be answered "eliminates", with evidence, before the dismissal stands.
    expect(onSubmit).not.toHaveBeenCalled();
  });

  test("records the verdict and reason for a decision that needs no gate", async () => {
    const { onSubmit, user } = setup();

    // Accepting a risk is a business decision rather than a falsification, so
    // it does not go through the gates — which makes it the clean case for
    // checking that what was typed is what gets recorded.
    await user.selectOptions(screen.getByRole("combobox", { name: /decision/i }), "acceptedRisk");
    await user.type(
      await screen.findByRole("textbox", { name: /reason/i }),
      "Accepted for the 1.2 release; tracked in SEC-441.",
    );
    await user.click(screen.getByRole("button", { name: /^save/i }));

    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    const request = onSubmit.mock.calls[0][0];
    expect(request.state).toBe("acceptedRisk");
    expect(request.reason).toBe("Accepted for the 1.2 release; tracked in SEC-441.");
    // The decision belongs to the project it was made in.
    expect(request.projectId).toBe("project-1");
  });

  test("an expiry in the past is refused rather than recorded", async () => {
    const { onSubmit, user } = setup();

    await user.selectOptions(screen.getByRole("combobox", { name: /decision/i }), "acceptedRisk");
    await user.type(
      await screen.findByRole("textbox", { name: /reason/i }),
      "Accepted for this release.",
    );
    await user.type(screen.getByLabelText(/expiry/i), "2020-01-01T09:00");
    await user.click(screen.getByRole("button", { name: /^save/i }));

    // An already-expired decision would return to the queue immediately, which
    // looks like the review never happened.
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByText(/expiry in the future/i)).toBeInTheDocument();
  });

  test("asks the falsification questions before accepting a vulnerability verdict", async () => {
    const { user } = setup();

    await user.selectOptions(screen.getByRole("combobox", { name: /decision/i }), "confirmed");

    // A verdict on a vulnerability is only as good as the questions behind it,
    // so confirming one surfaces the gates rather than taking the word for it.
    await waitFor(() => {
      expect(screen.getByText(/attacker-controlled/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/reachable in a production build/i)).toBeInTheDocument();
  });

  test("does not ask gate questions for a secret finding", async () => {
    const { user } = setup({ category: "secret", ruleId: "generic-password" });

    await user.selectOptions(screen.getByRole("combobox", { name: /decision/i }), "confirmed");

    // A leaked credential is not falsified by reachability analysis; it is
    // either a credential or it is not.
    expect(screen.queryByText(/attacker-controlled/i)).not.toBeInTheDocument();
  });

  test("cancelling records nothing", async () => {
    const { onSubmit, onCancel, user } = setup();
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalledOnce();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  test("a save already in flight cannot be submitted again", async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    render(
      <FindingReviewForm
        projectId="project-1"
        finding={finding()}
        saving
        error={null}
        onSubmit={onSubmit}
        onCancel={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: /saving|^save/i }));

    // Double-submitting appends two entries to an append-only history.
    expect(onSubmit).not.toHaveBeenCalled();
  });

  test("surfaces a failure to save rather than appearing to succeed", () => {
    render(
      <FindingReviewForm
        projectId="project-1"
        finding={finding()}
        saving={false}
        error={{
          code: "persistenceUnavailable",
          message: "the findings database is unavailable",
          detail: null,
          retryable: false,
        }}
        onSubmit={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText(/unavailable/i)).toBeInTheDocument();
  });
});
