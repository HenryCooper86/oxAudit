import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { HistoryScanPage } from "./HistoryScan";
import type { Finding, HistoryScanResult } from "../lib/types";
import { useAppStore } from "../lib/stores";
import { reconcileBackendWork, useScanWorkStore } from "../features/project-home/coordinator";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const scanHistorySecrets = vi.fn();
const cancelScanWork = vi.fn();
const listCanonicalRuns = vi.fn();
const loadCanonicalProjection = vi.fn();
vi.mock("../lib/api", () => ({
  api: { scanHistorySecrets: (...args: unknown[]) => scanHistorySecrets(...args),
    cancelScanWork: (...args: unknown[]) => cancelScanWork(...args), scanWorkStatus: async () => ({ active: null, recent: [] }),
    listCanonicalRuns: (...args: unknown[]) => listCanonicalRuns(...args), loadCanonicalProjection: (...args: unknown[]) => loadCanonicalProjection(...args) },
}));

beforeEach(() => {
  vi.clearAllMocks();
  useAppStore.setState({ activeProject: null, selectedProject: null, pageStatus: {} });
  useScanWorkStore.setState({ active: null, check: null, backend: { active: null, recent: [] }, lastTargets: {}, recoveryError: null });
  listCanonicalRuns.mockResolvedValue([]);
  cancelScanWork.mockResolvedValue(true);
});

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  id: "finding-1",
  category: "secret",
  ruleId: "aws-access-key-id",
  ruleName: "AWS Access Key ID",
  severity: "high",
  title: "AWS Access Key ID",
  description: "An AWS Access Key ID was found.",
  filePath: "src/deploy.sh",
  line: 2,
  column: 27,
  matchText: "export AWS_ACCESS_KEY_ID=[REDACTED]",
  context: "#!/bin/sh\nexport AWS_ACCESS_KEY_ID=[REDACTED]",
  language: "",
  cwe: null,
  cweExploited: false,
  cweExploitedCount: 0,
  recommendation: "Rotate the key.",
  entropy: 3.9,
  verified: null,
  analysis: "text",
  analysisGates: [],
  observationRunId: "",
  resolvedByRunId: null,
  fingerprintVersion: 1,
  fingerprint: "abc123",
  scope: null,
  scopeReason: null,
  review: null,
  reviewHistory: [],
  diffStatus: null,
  ...overrides,
});

const result = (overrides: Partial<HistoryScanResult> = {}): HistoryScanResult => ({
  runId: "saved-history",
  findings: [finding()],
  blobsScanned: 412,
  blobsSkipped: 3,
  truncated: false,
  limitNote: null,
  validation: null,
  ...overrides,
});

async function runScan(payload: HistoryScanResult, validate = false) {
  scanHistorySecrets.mockResolvedValue(payload);
  render(<HistoryScanPage />);
  await userEvent.clear(screen.getByRole("textbox", { name: /repository folder/i }));
  await userEvent.type(screen.getByRole("textbox", { name: /repository folder/i }), "/tmp/repo");
  if (validate) {
    await userEvent.click(screen.getByRole("switch", { name: /validate live against providers/i }));
  }
  const button = screen.getByRole("button", { name: /scan history$/i });
  await userEvent.click(button);
  await waitFor(() => expect(scanHistorySecrets).toHaveBeenCalledWith("/tmp/repo", validate, expect.any(String)));
  await waitFor(() => expect(button).not.toBeDisabled());
}

test("a completed history scan lists findings at their historical paths", async () => {
  await runScan(result());
  expect(await screen.findByText("aws-access-key-id")).toBeInTheDocument();
  expect(await screen.findByText("src/deploy.sh:2")).toBeInTheDocument();
  expect(screen.getByText(/1 shown · 1 historical secret/i)).toBeInTheDocument();
  // The redacted match is the evidence surface; the raw secret never exists here.
  expect(screen.getAllByText(/export AWS_ACCESS_KEY_ID=\[REDACTED\]/).length).toBeGreaterThan(0);
  expect(screen.queryByText(/stopped early/i)).not.toBeInTheDocument();
});

test("a truncated history scan says so instead of implying completeness", async () => {
  await runScan(
    result({ truncated: true, limitNote: "total scanned-bytes budget reached" }),
  );
  expect(screen.getByText("History scan stopped early")).toBeInTheDocument();
  expect(screen.getByText(/total scanned-bytes budget reached/i)).toBeInTheDocument();
  expect(screen.getByText(/findings below are partial/i)).toBeInTheDocument();
});

test("a clean history reports the blob count, not safety", async () => {
  await runScan(result({ findings: [], blobsScanned: 88 }));
  expect(screen.getByText(/no findings recorded — 88 blobs scanned/i)).toBeInTheDocument();
  expect(screen.getByText(/not proof no credential was ever typed/i)).toBeInTheDocument();
});

test("partial empty history scans never report a clean history", async () => {
  await runScan(result({ findings: [], truncated: true, limitNote: "time budget reached" }));
  expect(screen.getByText("History scan stopped early")).toBeInTheDocument();
  expect(screen.queryByText(/no secrets in history/i)).not.toBeInTheDocument();
  expect(useAppStore.getState().pageStatus["history-scan"]?.label).toMatch(/partial/i);
  expect(useAppStore.getState().pageStatus["history-scan"]?.label).not.toMatch(/clean/i);
});

test("filtering history findings also updates the displayed detail", async () => {
  await runScan(result({ findings: [
    finding({ title: "Hidden AWS credential", severity: "high" }),
    finding({ id: "finding-2", fingerprint: "def456", severity: "critical", title: "Visible critical credential", filePath: "src/critical.sh" }),
  ] }));
  await userEvent.selectOptions(screen.getByRole("combobox", { name: /finding severity/i }), "critical");
  expect(screen.getByText("Visible critical credential")).toBeInTheDocument();
  expect(screen.queryByText("Hidden AWS credential")).not.toBeInTheDocument();
  await userEvent.type(screen.getByRole("textbox", { name: /search history findings/i }), "no-match");
  expect(screen.queryByText("Visible critical credential")).not.toBeInTheDocument();
});

test.each(["completed", "failed"])("a %s history scan cannot overwrite status after its page unmounts", async (outcome) => {
  let complete!: (result: HistoryScanResult) => void;
  let fail!: (error: Error) => void;
  scanHistorySecrets.mockReturnValueOnce(new Promise((resolve, reject) => { complete = resolve; fail = reject; }));
  const previous = render(<HistoryScanPage />);
  await userEvent.type(screen.getByRole("textbox", { name: /repository folder/i }), "/tmp/repo");
  await userEvent.click(screen.getByRole("button", { name: /scan history$/i }));
  previous.unmount();
  expect(useAppStore.getState().pageStatus["history-scan"]).toBeUndefined();
  const old = useScanWorkStore.getState().active!;
  reconcileBackendWork({ active: null, recent: [{ operationId: old.operationId, kind: "history", target: "/tmp/repo", status: "completed", runId: "old-history", startedAtMs: 1, updatedAtMs: 2 }] });
  await runScan(result({ findings: [], blobsScanned: 2 }));
  const current = useAppStore.getState().pageStatus["history-scan"];
  await act(async () => {
    if (outcome === "completed") complete(result());
    else fail(new Error("previous scan failed"));
  });
  expect(useAppStore.getState().pageStatus["history-scan"]).toEqual(current);
});

test("a failed scan surfaces the error with a retry", async () => {
  scanHistorySecrets.mockRejectedValue(new Error("Git history unavailable: not a git repository"));
  render(<HistoryScanPage />);
  await userEvent.type(screen.getByRole("textbox", { name: /repository folder/i }), "/tmp/repo");
  await userEvent.click(screen.getByRole("button", { name: /scan history$/i }));
  expect(await screen.findByText("History scan failed")).toBeInTheDocument();
  expect(screen.getByText(/not a git repository/i)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
});

test("validation is opt-in: an untouched toggle scans without touching providers", async () => {
  await runScan(result());
  expect(screen.getByRole("switch", { name: /validate live against providers/i })).not.toBeChecked();
  expect(screen.queryByText(/provider check:/i)).not.toBeInTheDocument();
});

test("an opted-in run reports the provider verdicts and warns before touching the wire", async () => {
  await runScan(
    result({
      validation: { checked: 2, live: 1, rejected: 1, skippedNoValidator: 0, skippedUnpaired: 1, skippedLimit: 0, skippedNotKept: 0 },
    }),
    true,
  );
  expect(screen.getByRole("switch", { name: /validate live against providers/i })).toBeChecked();
  expect(screen.getByText(/provider check: 1 live, 1 rejected, 0 no answer, 1 not attempted/i)).toBeInTheDocument();
  expect(screen.getByText(/rotate it now/i)).toBeInTheDocument();
  expect(screen.getByText(/puts each leaked credential on the wire/i)).toBeInTheDocument();
});

test("a live finding is flagged as live in the list and the detail pane", async () => {
  await runScan(
    result({
      findings: [finding({ verified: true })],
      validation: { checked: 1, live: 1, rejected: 0, skippedNoValidator: 0, skippedUnpaired: 0, skippedLimit: 0, skippedNotKept: 0 },
    }),
    true,
  );
  expect(await screen.findAllByText(/^live$/i).then((nodes) => nodes.length)).toBeGreaterThan(0);
  expect(screen.getByText(/live — provider accepted it/i)).toBeInTheDocument();
  expect(screen.getByText(/deletion from history does not close it/i)).toBeInTheDocument();
});

test("a rejected finding says so without implying it is safe", async () => {
  await runScan(
    result({
      findings: [finding({ verified: false })],
      validation: { checked: 1, live: 0, rejected: 1, skippedNoValidator: 0, skippedUnpaired: 0, skippedLimit: 0, skippedNotKept: 0 },
    }),
    true,
  );
  expect(await screen.findByText(/provider rejected it/i)).toBeInTheDocument();
  expect(screen.getByText(/rotate it anyway/i)).toBeInTheDocument();
});

test("saved history restores Git object evidence without starting a new scan", async () => {
  useAppStore.setState({ activeProject: "/tmp/repo" });
  listCanonicalRuns.mockResolvedValue([{ id: "saved-history", kind: "history", targetLabel: "/tmp/repo", state: "completed", createdAtMs: 1, updatedAtMs: 2, attempt: 1, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] }]);
  loadCanonicalProjection.mockResolvedValue(result({ findingBlobIds: { "finding-1": "abc123gitblob" } }));
  render(<HistoryScanPage />);
  expect(await screen.findByText("abc123gitblob")).toBeInTheDocument();
  expect(screen.getByText(/saved-history/)).toBeInTheDocument();
  expect(scanHistorySecrets).not.toHaveBeenCalled();
  expect(loadCanonicalProjection).toHaveBeenCalledWith("saved-history");
  expect(screen.queryByText(/runs are not saved/)).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Open Export Center' }));
  expect(useAppStore.getState().exportHandoff).toEqual({ runId: 'saved-history' });
});

test("history cancellation is scoped and a delayed completed response cannot publish clean history", async () => {
  let finish!: (value: HistoryScanResult) => void;
  scanHistorySecrets.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  render(<HistoryScanPage />);
  await userEvent.type(screen.getByRole("textbox", { name: /repository folder/i }), "/tmp/repo");
  await userEvent.click(screen.getByRole("button", { name: /scan history$/i }));
  const operationId = scanHistorySecrets.mock.calls[0][2];
  await userEvent.click(screen.getByRole("button", { name: /^cancel$/i }));
  expect(cancelScanWork).toHaveBeenCalledWith(operationId);
  await act(async () => finish(result({ findings: [], blobsScanned: 2 })));
  expect(screen.queryByText(/no secrets in history/)).not.toBeInTheDocument();
  expect(useAppStore.getState().pageStatus["history-scan"]?.label).toMatch(/cancelled/i);
});

test("10,000 historical findings render a bounded page and retain selection across page changes", async () => {
  const findings = Array.from({ length: 10_000 }, (_, index) => finding({ id: `finding-${index}`, fingerprint: `fp-${index}`, ruleId: `rule-${index}`, filePath: `src/${index.toString().padStart(5, "0")}.ts`, title: `Historical ${index}` }));
  useAppStore.setState({ activeProject: '/tmp/repo' });
  listCanonicalRuns.mockResolvedValue([{ id: 'saved-history', kind: 'history', targetLabel: '/tmp/repo', state: 'completed', attempt: 1, createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] }]);
  loadCanonicalProjection.mockResolvedValue(result({ findings }));
  const started = performance.now();
  render(<HistoryScanPage />);
  const list = await screen.findByRole("list", { name: "Historical secret findings" });
  const renderMs = performance.now() - started;
  expect(list.children).toHaveLength(50);
  const moved = performance.now();
  fireEvent.click(screen.getByRole("button", { name: "Last page of historical findings" }));
  const lastPageMs = performance.now() - moved;
  await userEvent.click(screen.getByText("rule-9999"));
  expect(screen.getByText("Historical 9999")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "First page of historical findings" }));
  await userEvent.click(screen.getByRole("button", { name: "Last page of historical findings" }));
  expect(screen.getByText("rule-9999").closest("button")).toHaveAttribute("aria-current", "true");
  console.info('result-list-measurement', JSON.stringify({ list: 'history', records: 10_000, renderedRows: 50, renderMs, lastPageMs, environment: 'jsdom' }));
});

test('history reopens the latest canonical receipt after restart without a selected project', async () => {
  useAppStore.setState({ activeProject: null, selectedProject: null });
  listCanonicalRuns.mockResolvedValue([{ id: 'latest-history', kind: 'history', targetLabel: '/tmp/restarted-repo', state: 'incomplete', attempt: 1, createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] }]);
  loadCanonicalProjection.mockResolvedValue(result({ runId: 'latest-history', findings: [], state: 'incomplete', gitContext: { headBefore: 'old-head', headAfter: null, refsBefore: [], refsAfter: [], refsCompleteAfter: false, contextChanged: null } }));
  render(<HistoryScanPage />);
  const evidence = await screen.findByRole('region', { name: 'History evidence summary' });
  expect(within(evidence).getByText('latest-history')).not.toBeVisible();
  await userEvent.click(within(evidence).getByRole('button', { name: 'Evidence details' }));
  expect(within(evidence).getByText('latest-history')).toBeVisible();
  expect(screen.getByRole('textbox', { name: /repository folder/i })).toHaveValue('/tmp/restarted-repo');
  expect(within(evidence).getByText(/Git history coverage changed or is unknown/)).toBeVisible();
  expect(screen.queryByText(/No secrets in history/)).not.toBeInTheDocument();
  expect(scanHistorySecrets).not.toHaveBeenCalled();
});
