import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { sourceMetadata, sourcePage } from "../../../tests/fixtures/pagedResults";
import { projectContext, projectSettings, sourceResult } from "../../../tests/fixtures/projectHome";
import { api } from "../../lib/api";
import { useAppStore } from "../../lib/stores";
import type { Finding, ReviewRecord, ScanRunDetail, ScanRunSummary, SourceRunMetadata } from "../../lib/types";
import { SourceScanPage } from "../../pages/SourceScan";
import { useScanWorkStore } from "../project-home/coordinator";

vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/api/webview", () => ({ getCurrentWebview: () => ({ onDragDropEvent: async () => () => {} }) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

function deferred<T>() {
  // Node 22 supports this API; the project's ES2020 library omits its type.
  const constructor = Promise as unknown as {
    withResolvers(): { promise: Promise<T>; resolve(value: T): void };
  };
  return constructor.withResolvers();
}

function makeFinding(ruleName: string, observationRunId: string, fingerprint: string): Finding {
  return {
    id: `finding-${fingerprint}`,
    category: "vulnerability",
    ruleId: "js-eval",
    ruleName,
    severity: "high",
    title: ruleName,
    description: "Untrusted input reaches eval.",
    filePath: "src/app.js",
    line: 3,
    column: 8,
    matchText: "eval(input)",
    context: "eval(input)",
    language: "javascript",
    cwe: "CWE-95",
    cweExploited: false,
    cweExploitedCount: 0,
    recommendation: "Use a safe API.",
    entropy: null,
    verified: null,
    analysis: "syntax",
    analysisGates: [],
    observationRunId,
    resolvedByRunId: null,
    fingerprintVersion: 1,
    fingerprint,
    scope: "production",
    scopeReason: null,
    review: null,
    reviewHistory: [],
    diffStatus: "new",
  };
}

function makeRun(path: string, runId: string, ruleName: string, fingerprint: string): ScanRunDetail {
  const base = sourceResult(path);
  return {
    ...base,
    projectId: path,
    runId,
    summary: { ...base.summary, path, totalFindings: 1, vulnerabilitiesFound: 1, high: 1 },
    findings: [makeFinding(ruleName, runId, fingerprint)],
  };
}

function runSummary(runId: string, path: string, totalFindings: number): ScanRunSummary {
  return {
    runId,
    projectId: path,
    status: "completed",
    startedAt: "2026-09-07T00:00:00Z",
    completedAt: "2026-09-07T00:01:00Z",
    totalFindings,
    newFindings: totalFindings,
    resolvedFindings: 0,
    severityCounts: { critical: 0, high: totalFindings, medium: 0, low: 0, info: 0 },
  };
}

const firstRun = makeRun("/first", "s", "Unsafe eval", "fp-first");
const otherRun = makeRun("/first", "other", "Stale history finding", "fp-other");
const secondRun = makeRun("/second", "second-run", "Second project finding", "fp-second");
const scannedRun = makeRun("/first", "scanned", "Scanned finding", "fp-scanned");

const review: ReviewRecord = {
  id: "review-1",
  projectId: "/first",
  fingerprintVersion: 1,
  fingerprint: "fp-first",
  state: "acceptedRisk",
  reason: "Temporary business exception.",
  evidence: null,
  entryPoint: null,
  dataFlow: null,
  gates: [],
  decidingGate: null,
  expiresAt: null,
  origin: "local",
  policyHash: null,
  updatedAt: "2026-09-08T00:00:00Z",
  supersededAt: null,
};

beforeEach(() => {
  useAppStore.setState({
    activeProject: "/first",
    selectedProject: null,
    projectHandoff: null,
    settings: projectSettings,
    settingsLoadError: false,
  });
  useScanWorkStore.setState({ active: null, check: null, backend: { active: null, recent: [] } });
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([]);
  vi.spyOn(api, "inspectSourceGit").mockRejectedValue("No Git");
  vi.spyOn(api, "setActiveProject").mockResolvedValue();
  vi.spyOn(api, "scanWorkStatus").mockResolvedValue({ active: null, recent: [] });
  vi.spyOn(api, "scanProject").mockResolvedValue(scannedRun);
  vi.spyOn(api, "saveFindingReview").mockResolvedValue(review);
  vi.spyOn(api, "inspectSourceProject").mockImplementation(async (path) => ({
    ...projectContext(path),
    lastCompletedRunId: path === "/first" ? "s" : path === "/second" ? "second-run" : null,
  }));
  vi.spyOn(api, "listSourceRuns").mockImplementation(async (projectId) => {
    if (projectId === "/first") return [runSummary("s", "/first", 1), runSummary("other", "/first", 0)];
    if (projectId === "/second") return [runSummary("second-run", "/second", 1)];
    return [];
  });
  const metadataFor = (id: string): SourceRunMetadata =>
    id === "second-run" ? sourceMetadata(secondRun) : id === "other" ? sourceMetadata(otherRun) : sourceMetadata(firstRun);
  vi.spyOn(api, "loadSourceRunMetadata").mockImplementation(async (id) => metadataFor(id));
  vi.spyOn(api, "loadSourceRunPage").mockImplementation(async (id, query) => {
    const run = id === "second-run" ? secondRun : id === "other" ? otherRun : firstRun;
    return sourcePage(run, query);
  });
});

function clickOtherHistoryRow() {
  const history = within(screen.getByRole("region", { name: "Run history" }));
  fireEvent.click(history.getByText("0 findings").closest("button")!);
}

test("changing path during a pending history load does not leave findings blank", async () => {
  let resolveOther!: (value: SourceRunMetadata) => void;
  vi.mocked(api.loadSourceRunMetadata).mockImplementation(async (id) => {
    if (id === "other") return new Promise<SourceRunMetadata>((resolve) => { resolveOther = resolve; });
    return sourceMetadata(id === "second-run" ? secondRun : firstRun);
  });

  render(<SourceScanPage />);
  expect(await screen.findByRole("heading", { name: "Unsafe eval" })).toBeInTheDocument();

  clickOtherHistoryRow();
  fireEvent.change(screen.getByLabelText("Project folder path"), { target: { value: "/second" } });

  expect(await screen.findByRole("heading", { name: "Second project finding" })).toBeInTheDocument();

  await act(async () => resolveOther(sourceMetadata(otherRun)));

  expect(screen.getByRole("heading", { name: "Second project finding" })).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Stale history finding" })).not.toBeInTheDocument();
});

test("switching projects during a pending review save re-enables the review controls", async () => {
  let resolveSave!: (value: ReviewRecord) => void;
  vi.mocked(api.saveFindingReview).mockImplementation(() => new Promise<ReviewRecord>((resolve) => { resolveSave = resolve; }));

  render(<SourceScanPage />);
  await screen.findByRole("heading", { name: "Unsafe eval" });

  fireEvent.click(screen.getByRole("button", { name: "Review finding" }));
  fireEvent.change(screen.getByLabelText("Decision"), { target: { value: "acceptedRisk" } });
  fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Temporary business exception." } });

  fireEvent.click(screen.getByRole("button", { name: "Save review" }));
  expect(screen.getByRole("button", { name: "Saving…" })).toBeDisabled();

  await act(async () => useAppStore.getState().setActiveProject("/second"));
  await screen.findByRole("heading", { name: "Second project finding" });

  await act(async () => resolveSave(review));

  fireEvent.click(screen.getByRole("button", { name: "Review finding" }));
  fireEvent.change(screen.getByLabelText("Decision"), { target: { value: "acceptedRisk" } });
  fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Temporary business exception." } });

  expect(screen.getByRole("button", { name: "Save review" })).toBeEnabled();
});

test("history navigation during an active scan cannot drop the scan result", async () => {
  const scan = deferred<ScanRunDetail>();
  vi.mocked(api.scanProject).mockReturnValue(scan.promise);

  render(<SourceScanPage />);
  await screen.findByRole("heading", { name: "Unsafe eval" });

  fireEvent.click(screen.getByRole("button", { name: "Run scan" }));
  await waitFor(() => expect(api.scanProject).toHaveBeenCalled());

  const history = within(screen.getByRole("region", { name: "Run history" }));
  const otherButton = history.getByText("0 findings").closest("button")!;
  expect(otherButton).toBeDisabled();
  fireEvent.click(otherButton);

  await act(async () => scan.resolve(scannedRun));
  expect(await screen.findByRole("heading", { name: "Scanned finding" })).toBeInTheDocument();
});

test("a stale history load cannot overwrite a fresh scan result", async () => {
  let resolveOther!: (value: SourceRunMetadata) => void;
  vi.mocked(api.loadSourceRunMetadata).mockImplementation(async (id) => {
    if (id === "other") return new Promise<SourceRunMetadata>((resolve) => { resolveOther = resolve; });
    return sourceMetadata(id === "second-run" ? secondRun : firstRun);
  });

  render(<SourceScanPage />);
  await screen.findByRole("heading", { name: "Unsafe eval" });

  clickOtherHistoryRow();
  fireEvent.click(screen.getByRole("button", { name: "Run scan" }));
  expect(await screen.findByRole("heading", { name: "Scanned finding" })).toBeInTheDocument();

  await act(async () => resolveOther(sourceMetadata(otherRun)));

  expect(screen.getByRole("heading", { name: "Scanned finding" })).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Stale history finding" })).not.toBeInTheDocument();
});

test("an older same-run request cannot clear a newer history load", async () => {
  const firstA = deferred<SourceRunMetadata>();
  const secondA = deferred<SourceRunMetadata>();
  const pendingB = deferred<SourceRunMetadata>();
  const runB = makeRun("/first", "history-b", "History B finding", "fp-b");
  vi.mocked(api.listSourceRuns).mockResolvedValue([
    runSummary("s", "/first", 1),
    runSummary("other", "/first", 0),
    runSummary("history-b", "/first", 2),
  ]);
  let requestedA = false;
  vi.mocked(api.loadSourceRunMetadata).mockImplementation((id) => {
    if (id === "other") {
      const pending = requestedA ? secondA : firstA;
      requestedA = true;
      return pending.promise;
    }
    return id === "history-b" ? pendingB.promise : Promise.resolve(sourceMetadata(firstRun));
  });
  render(<SourceScanPage />);
  await screen.findByRole("heading", { name: "Unsafe eval" });
  const history = within(screen.getByRole("region", { name: "Run history" }));
  const buttonA = history.getByText("0 findings").closest("button")!;
  const buttonB = history.getByText("2 findings").closest("button")!;
  fireEvent.click(buttonA);
  fireEvent.click(buttonB);
  fireEvent.click(buttonA);

  await act(async () => firstA.resolve(sourceMetadata(otherRun)));
  expect(buttonA).toBeDisabled();
  expect(screen.queryByRole("heading", { name: "Unsafe eval" })).not.toBeInTheDocument();
  await act(async () => secondA.resolve(sourceMetadata(otherRun)));
  expect(await screen.findByRole("heading", { name: "Stale history finding" })).toBeInTheDocument();
  await act(async () => pendingB.resolve(sourceMetadata(runB)));
  expect(screen.queryByRole("heading", { name: "History B finding" })).not.toBeInTheDocument();
});
