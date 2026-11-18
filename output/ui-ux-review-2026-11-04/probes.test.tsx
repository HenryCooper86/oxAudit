// Temporary source-review probes. Passing means the reported behavior was reproduced,
// not that it is desirable or fixed. No browser layout or screen reader is simulated.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { CommandPalette } from "./components/workbench/CommandPalette";
import { FindingDetail } from "./components/FindingDetail";
import { loadProjectHome } from "./features/project-home/history";
import { api } from "./lib/api";
import type { Finding } from "./lib/types";

const finding: Finding = {
  id: "audit-finding", category: "vulnerability", ruleId: "js-eval",
  ruleName: "eval() usage", severity: "high", title: "eval() usage",
  description: "Untrusted input is evaluated as code.", filePath: "src/handler.js",
  line: 3, column: 8, matchText: "eval(input)", context: "return eval(input);",
  language: "javascript", cwe: "CWE-95", cweExploited: false,
  cweExploitedCount: 0, recommendation: "Use a safe parser.", entropy: null,
  verified: null, analysis: "syntax", analysisGates: [], observationRunId: "audit-run",
  resolvedByRunId: null, fingerprintVersion: 1, fingerprint: "audit-fp",
  scope: "production", scopeReason: null, review: null, reviewHistory: [], diffStatus: "new",
};

function detail(value = finding) {
  return <FindingDetail projectId="audit-project" finding={value}
    savingReview={false} reviewError={null} onSaveReview={vi.fn().mockResolvedValue(undefined)}
    onCopy={vi.fn()} onOpenFile={vi.fn()} />;
}

beforeEach(() => { vi.clearAllMocks(); });

test("UX-01: Shift+Tab escapes the modal palette; Escape then does not close it", async () => {
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([]);
  const onClose = vi.fn();
  const user = userEvent.setup();
  render(<><button>Background action</button><CommandPalette open onClose={onClose} /></>);
  await waitFor(() => expect(screen.getByRole("textbox", { name: "Search commands" })).toHaveFocus());
  await user.tab({ shift: true });
  expect(screen.getByRole("button", { name: "Background action" })).toHaveFocus();
  expect(screen.getByRole("dialog", { name: "Command palette" })).toHaveAttribute("aria-modal", "true");
  await user.keyboard("{Escape}");
  expect(onClose).not.toHaveBeenCalled();
  expect(screen.getByRole("dialog", { name: "Command palette" })).toBeInTheDocument();
});

test("UX-02: Review finding appends a form after the detail without focus or scroll handoff", async () => {
  render(detail());
  const user = userEvent.setup();
  const scroll = vi.spyOn(Element.prototype, "scrollIntoView");
  scroll.mockClear();
  const trigger = screen.getByRole("button", { name: "Review finding" });
  await user.click(trigger);
  const form = screen.getByRole("form", { name: "Review finding" });
  expect(form).toBeInTheDocument();
  expect(trigger).toHaveFocus();
  expect(screen.getByLabelText("Decision")).not.toHaveFocus();
  expect(scroll).not.toHaveBeenCalled();
  const recommendation = screen.getByRole("region", { name: "Recommendation" });
  expect(recommendation.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
});

test("UX-03: Changing findings discards an unsaved review draft with no recovery", async () => {
  const view = render(detail());
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Review finding" }));
  await user.selectOptions(screen.getByLabelText("Decision"), "acceptedRisk");
  await user.type(screen.getByLabelText("Reason"), "Needs team approval before recording");
  view.rerender(detail({ ...finding, id: "other", fingerprint: "other-fp" }));
  expect(screen.queryByRole("form", { name: "Review finding" })).not.toBeInTheDocument();
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  view.rerender(detail());
  await user.click(screen.getByRole("button", { name: "Review finding" }));
  expect(screen.getByLabelText("Decision")).toHaveValue("candidate");
  expect(screen.queryByDisplayValue("Needs team approval before recording")).not.toBeInTheDocument();
});

test("UX-04: Failure to load one project's runs rejects all project-home history", async () => {
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([
    { projectId: "healthy", canonicalPath: "/healthy", displayName: "Healthy", lastOpenedAt: "2026-11-04T00:00:00Z", lastCompletedRunId: null },
    { projectId: "unavailable", canonicalPath: "/unavailable", displayName: "Unavailable", lastOpenedAt: "2026-11-04T00:00:00Z", lastCompletedRunId: null },
  ] as Awaited<ReturnType<typeof api.listSourceProjects>>);
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([]);
  vi.spyOn(api, "listSourceRuns").mockImplementation(async (id) => {
    if (id === "unavailable") throw new Error("One history request failed");
    return [];
  });
  await expect(loadProjectHome()).rejects.toThrow("One history request failed");
  expect(api.listSourceRuns).toHaveBeenCalledWith("healthy", 50);
});

test("UX-05: Invalid review expiry has a visible error but no input error association", async () => {
  render(detail());
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Review finding" }));
  await user.selectOptions(screen.getByLabelText("Decision"), "acceptedRisk");
  await user.type(screen.getByLabelText("Reason"), "Temporary exception");
  const expiry = screen.getByLabelText("Optional expiry");
  fireEvent.change(expiry, { target: { value: "2020-01-01T12:00" } });
  expect(screen.getByText("Choose a valid expiry in the future.")).toBeInTheDocument();
  expect(expiry).not.toHaveAttribute("aria-invalid");
  expect(expiry).not.toHaveAttribute("aria-describedby");
  expect(screen.getByRole("button", { name: "Save review" })).toBeDisabled();
});
