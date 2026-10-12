import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { sourceMetadata, sourcePage } from "../../../tests/fixtures/pagedResults";
import { projectContext, projectSettings, sourceResult } from "../../../tests/fixtures/projectHome";
import { api } from "../../lib/api";
import { useAppStore } from "../../lib/stores";
import type { Finding, ReviewRecord, ScanRunDetail } from "../../lib/types";
import { SourceScanPage } from "../../pages/SourceScan";
import { useScanWorkStore } from "../project-home/coordinator";

vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/api/webview", () => ({ getCurrentWebview: () => ({ onDragDropEvent: async () => () => {} }) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const finding: Finding = {
  id: "finding-1", category: "vulnerability", ruleId: "js-eval", ruleName: "Unsafe eval",
  severity: "high", title: "Unsafe eval", description: "Untrusted input reaches eval.",
  filePath: "src/app.js", line: 3, column: 8, matchText: "eval(input)", context: "eval(input)",
  language: "javascript", cwe: "CWE-95", cweExploited: false, cweExploitedCount: 0,
  recommendation: "Use a safe API.", entropy: null, verified: null,
  analysis: "syntax", analysisGates: [], observationRunId: "s", resolvedByRunId: null,
  fingerprintVersion: 1, fingerprint: "fp-1", scope: "production", scopeReason: null,
  review: null, reviewHistory: [], diffStatus: "new",
};
const original: ScanRunDetail = {
  ...sourceResult(), findings: [finding],
  summary: { ...sourceResult().summary, totalFindings: 1, vulnerabilitiesFound: 1, high: 1 },
};
const review: ReviewRecord = {
  id: "review-1", projectId: original.projectId, fingerprintVersion: 1, fingerprint: "fp-1",
  state: "acceptedRisk", reason: "Temporary business exception.", evidence: null,
  entryPoint: null, dataFlow: null, gates: [], decidingGate: null, expiresAt: null,
  origin: "local", policyHash: null, updatedAt: "2026-09-08T00:00:00Z", supersededAt: null,
};
let durableRun: ScanRunDetail;

beforeEach(() => {
  durableRun = original;
  useAppStore.setState({
    activeProject: original.summary.path, selectedProject: null, projectHandoff: null,
    settings: projectSettings, settingsLoadError: false,
  });
  useScanWorkStore.setState({ active: null, check: null });
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([]);
  vi.spyOn(api, "listSourceRuns").mockResolvedValue([]);
  vi.spyOn(api, "inspectSourceGit").mockRejectedValue("No Git");
  vi.spyOn(api, "inspectSourceProject").mockImplementation(async path => ({
    ...projectContext(path), lastCompletedRunId: "s",
  }));
  vi.spyOn(api, "setActiveProject").mockResolvedValue();
  vi.spyOn(api, "loadSourceRunMetadata").mockImplementation(async () => sourceMetadata(durableRun));
  vi.spyOn(api, "loadSourceRunPage").mockImplementation(async (_id, query) => sourcePage(durableRun, query));
  vi.spyOn(api, "saveFindingReview").mockImplementation(async () => {
    durableRun = { ...original, findings: [{ ...finding, review, reviewHistory: [review] }] };
    return review;
  });
});

async function openAcceptedRiskReview() {
  fireEvent.click(await screen.findByRole("button", { name: "Review finding" }));
  fireEvent.change(screen.getByLabelText("Decision"), { target: { value: "acceptedRisk" } });
  fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Temporary business exception." } });
}

test("Retry refreshes the current run after a saved review's metadata refresh fails", async () => {
  render(<SourceScanPage />);
  await openAcceptedRiskReview();
  expect(screen.getByRole("tab", { name: "Open 1" })).toBeInTheDocument();
  vi.mocked(api.loadSourceRunMetadata).mockRejectedValueOnce(new Error("Database temporarily unavailable"));

  fireEvent.click(screen.getByRole("button", { name: "Save review" }));
  const retry = await screen.findByRole("button", { name: "Retry" });
  expect(screen.getByRole("tab", { name: "Open 1" })).toBeInTheDocument();
  fireEvent.click(retry);

  fireEvent.click(await screen.findByRole("tab", { name: "Closed 1" }));
  const detail = await screen.findByRole("region", { name: "Finding detail" });
  const currentReview = await within(detail).findByRole("region", { name: "Current review" });
  expect(within(currentReview).getByText("Temporary business exception.")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Retry" })).not.toBeInTheDocument();
  expect(screen.queryByText("The review was saved, but refreshed results could not be loaded.")).not.toBeInTheDocument();
});

test("a failed review refresh cannot publish its recovery error into a different project", async () => {
  const second: ScanRunDetail = {
    ...original, projectId: "/second", runId: "second-run", summary: { ...original.summary, path: "/second" },
    findings: [{ ...finding, ruleName: "Second project finding", observationRunId: "second-run" }],
  };
  vi.mocked(api.inspectSourceProject).mockImplementation(async path => ({
    ...projectContext(path), lastCompletedRunId: path === "/second" ? "second-run" : "s",
  }));
  vi.mocked(api.loadSourceRunMetadata).mockImplementation(async id => sourceMetadata(id === "second-run" ? second : durableRun));
  vi.mocked(api.loadSourceRunPage).mockImplementation(async (id, query) => sourcePage(id === "second-run" ? second : durableRun, query));
  render(<SourceScanPage />);
  await openAcceptedRiskReview();
  let rejectRefresh!: (error: Error) => void;
  vi.mocked(api.loadSourceRunMetadata).mockReturnValueOnce(new Promise((_resolve, reject) => { rejectRefresh = reject; }));

  await act(async () => fireEvent.click(screen.getByRole("button", { name: "Save review" })));
  await act(async () => useAppStore.getState().setActiveProject("/second"));
  await screen.findByRole("heading", { name: "Second project finding" });
  await act(async () => rejectRefresh(new Error("Previous project refresh failed")));

  expect(screen.queryByText("The review was saved, but refreshed results could not be loaded.")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Retry" })).not.toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Second project finding" })).toBeInTheDocument();
});
