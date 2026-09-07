import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { api } from "../../lib/api";
import { useAppStore } from "../../lib/stores";
import { useScanWorkStore, acquireScan, releaseScan } from "../project-home/coordinator";
import { SourceScanPage } from "../../pages/SourceScan";
import { SettingsPage } from "../../pages/SettingsPage";
import { projectSettings, projectContext, sourceResult } from "../../../tests/fixtures/projectHome";
import type { Finding, RecheckSourceResult } from "../../lib/types";
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/api/webview", () => ({ getCurrentWebview: () => ({ onDragDropEvent: async () => () => {} }) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
const finding = { id: "finding", title: "eval() usage", language: "javascript", cwe: "CWE-95", cweExploited: false, cweExploitedCount: 0, entropy: null, verified: null, scopeReason: null, resolvedByRunId: null, fingerprint: "fp", fingerprintVersion: 1, category: "vulnerability", ruleId: "js-eval", ruleName: "eval() usage", severity: "high", filePath: "space 😀.js", line: 3, column: 8, matchText: "eval(input)", context: "", description: "Code execution", recommendation: "Avoid eval", scope: "production", analysis: "syntax", analysisGates: [], review: null, reviewHistory: [], observationRunId: "s", diffStatus: "new" } as Finding;
const original = { ...sourceResult(), findings: [finding] };
const options = { path: original.summary.path, includeGit: true, followSymlinks: false, maxFileSizeKb: 73, scanSecrets: false, scanVulnerabilities: true, extraIgnoredDirs: ["original"], ignoreInvalidPolicy: false };
const receipt: RecheckSourceResult = { run: { ...sourceResult(), runId: "next" }, options };
beforeEach(() => {
  useAppStore.setState({ activeProject: original.summary.path, selectedProject: null, projectHandoff: null, settings: projectSettings, settingsLoadError: false });
  useScanWorkStore.setState({ active: null, check: null });
  vi.mocked(invoke).mockResolvedValue(undefined);
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([]);
  vi.spyOn(api, "listSourceRuns").mockResolvedValue([]);
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([]);
  vi.spyOn(api, "inspectSourceGit").mockRejectedValue("No Git");
  vi.spyOn(api, "inspectSourceProject").mockImplementation(async path => ({ ...projectContext(path), lastCompletedRunId: "s" }));
  vi.spyOn(api, "loadSourceRun").mockResolvedValue(original);
  vi.spyOn(api, "setActiveProject").mockResolvedValue();
});
test("settings saves preferred editor through the settings transaction", async () => {
  vi.spyOn(api, "getTotalUsage").mockRejectedValue("none");
  vi.spyOn(api, "saveSettings").mockImplementation(async request => ({ settings: request.settings }));
  render(<SettingsPage />);
  fireEvent.change(screen.getByLabelText("Preferred editor"), { target: { value: "vscode" } });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(useAppStore.getState().settings?.editor).toBe("vscode"));
  expect(api.saveSettings).toHaveBeenCalledWith(expect.objectContaining({ settings: expect.objectContaining({ editor: "vscode" }) }));
});
test("Open file sends captured root and unmodified finding byte position", async () => {
  render(<SourceScanPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Open file" }));
  expect(invoke).toHaveBeenCalledWith("open_scan_finding", { root: original.summary.path, relativePath: finding.filePath, line: 3, column: 8 });
});
test("recheck retains original evidence and links covered observation using original options", async () => {
  vi.spyOn(api, "recheckSourceRun").mockResolvedValue(receipt);
  vi.spyOn(api, "compareSourceRuns").mockResolvedValue([{ ...finding, diffStatus: "resolved", resolvedByRunId: "next" }]);
  render(<SourceScanPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Recheck finding" }));
  await screen.findByText(/No longer detected in the covered file/);
  expect(api.recheckSourceRun).toHaveBeenCalledWith("s", original.projectId);
  expect(api.compareSourceRuns).toHaveBeenCalledWith("next", "s", true);
  expect(screen.getByText("eval(input)", { selector: "pre" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Open recheck run next" })).toBeEnabled();
});
test("recheck respects shared scan ownership", async () => {
  acquireScan("project", "/other", "Scanning source");
  render(<SourceScanPage />);
  expect(await screen.findByRole("button", { name: "Recheck finding" })).toBeDisabled();
});
test.each(["cancelled", "failed", "wrongProject", "unsaved"])("recheck %s cannot claim covered absence", async mode => {
  const response = mode === "wrongProject" ? { ...receipt, run: { ...receipt.run, projectId: "other" } } : mode === "unsaved" ? { ...receipt, run: { ...receipt.run, persistence: { status: "notSaved", retryToken: "retry" } as const } } : receipt;
  const request = vi.spyOn(api, "recheckSourceRun");
  if (mode === "cancelled" || mode === "failed") request.mockRejectedValue({ code: mode === "cancelled" ? "scanCancelled" : "scanFailed", message: mode, retryable: false });
  else request.mockResolvedValue(response);
  render(<SourceScanPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Recheck finding" }));
  await screen.findByText(mode === "cancelled" ? /Recheck cancelled/ : /Recheck not evaluated/);
  expect(screen.queryByText(/No longer detected in the covered file/)).not.toBeInTheDocument();
});
test("a pending recheck cannot publish into a different project", async () => {
  let finish!: (value: RecheckSourceResult) => void;
  vi.spyOn(api, "recheckSourceRun").mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const compare = vi.spyOn(api, "compareSourceRuns");
  render(<SourceScanPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Recheck finding" }));
  await act(async () => useAppStore.getState().setActiveProject("/second"));
  await act(async () => finish(receipt));
  expect(compare).not.toHaveBeenCalled();
  expect(screen.queryByText(/No longer detected/)).not.toBeInTheDocument();
  expect(useAppStore.getState().activeProject).toBe("/second");
});
test("new-run navigation uses durable history and clears the recheck selection view", async () => {
  vi.spyOn(api, "recheckSourceRun").mockResolvedValue(receipt);
  vi.spyOn(api, "compareSourceRuns").mockResolvedValue([{ ...finding, diffStatus: "resolved", resolvedByRunId: "next" }]);
  vi.mocked(api.loadSourceRun).mockImplementation(async id => id === "next" ? receipt.run : original);
  render(<SourceScanPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Recheck finding" }));
  fireEvent.click(await screen.findByRole("button", { name: "Open recheck run next" }));
  await screen.findByText(/No findings were detected in 1 scanned files/);
  expect(api.loadSourceRun).toHaveBeenCalledWith("next");
  expect(screen.queryByLabelText("Finding recheck outcome")).not.toBeInTheDocument();
});

const unsavedReceipt: RecheckSourceResult = { ...receipt, run: { ...receipt.run, persistence: { status: "notSaved", retryToken: "recheck-retry" } } };
test("unsaved recheck retains its receipt and compares only after a successful guarded save", async () => {
  vi.spyOn(api, "recheckSourceRun").mockResolvedValue(unsavedReceipt);
  const compare = vi.spyOn(api, "compareSourceRuns").mockResolvedValue([{ ...finding, diffStatus: "resolved", resolvedByRunId: "next" }]);
  let finish!: (value: typeof receipt.run) => void;
  const save = vi.spyOn(api, "retrySourceRunSave").mockReturnValue(new Promise(resolve => { finish = resolve; }));
  render(<SourceScanPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Recheck finding" }));
  const retry = await screen.findByRole("button", { name: "Retry recheck save" });
  expect(compare).not.toHaveBeenCalled();
  expect(screen.getByText("eval(input)", { selector: "pre" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Recheck finding" })).toBeDisabled();
  fireEvent.click(retry);
  expect(save).toHaveBeenCalledWith("recheck-retry");
  expect(screen.getByRole("button", { name: "Saving recheck…" })).toBeDisabled();
  expect(useScanWorkStore.getState().active?.stage).toBe("Saving recheck");
  expect(compare).not.toHaveBeenCalled();
  await act(async () => finish(receipt.run));
  await screen.findByText(/No longer detected in the covered file/);
  expect(compare).toHaveBeenCalledWith("next", "s", true);
  expect(screen.queryByRole("button", { name: "Retry recheck save" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Open recheck run next" })).toBeEnabled();
  expect(screen.getByText("eval(input)", { selector: "pre" })).toBeInTheDocument();
  expect(useScanWorkStore.getState().active).toBeNull();
});
test.each(["wrongProject", "wrongRun", "stillUnsaved", "failed"])("recheck save %s preserves recovery and never compares", async mode => {
  vi.spyOn(api, "recheckSourceRun").mockResolvedValue(unsavedReceipt);
  const compare = vi.spyOn(api, "compareSourceRuns");
  const save = vi.spyOn(api, "retrySourceRunSave");
  if (mode === "failed") save.mockRejectedValue(new Error("database busy"));
  else save.mockResolvedValue(mode === "wrongProject" ? { ...receipt.run, projectId: "other" } : mode === "wrongRun" ? { ...receipt.run, runId: "other" } : unsavedReceipt.run);
  render(<SourceScanPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Recheck finding" }));
  fireEvent.click(await screen.findByRole("button", { name: "Retry recheck save" }));
  await screen.findByText(/Recheck save failed/);
  expect(compare).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Retry recheck save" })).toBeEnabled();
  expect(screen.queryByRole("button", { name: "Open recheck run next" })).not.toBeInTheDocument();
});
test("a stale recheck save cannot compare or publish into another project", async () => {
  vi.spyOn(api, "recheckSourceRun").mockResolvedValue(unsavedReceipt);
  const compare = vi.spyOn(api, "compareSourceRuns");
  let finish!: (value: typeof receipt.run) => void;
  vi.spyOn(api, "retrySourceRunSave").mockReturnValue(new Promise(resolve => { finish = resolve; }));
  render(<SourceScanPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Recheck finding" }));
  fireEvent.click(await screen.findByRole("button", { name: "Retry recheck save" }));
  await act(async () => useAppStore.getState().setActiveProject("/second"));
  await act(async () => finish(receipt.run));
  expect(compare).not.toHaveBeenCalled();
  expect(screen.queryByLabelText("Finding recheck outcome")).not.toBeInTheDocument();
  expect(useAppStore.getState().activeProject).toBe("/second");
  expect(useScanWorkStore.getState().active).toBeNull();
});

test("a recheck save that lost ownership cannot compare or release a newer owner", async () => {
  vi.spyOn(api, "recheckSourceRun").mockResolvedValue(unsavedReceipt);
  const compare = vi.spyOn(api, "compareSourceRuns");
  let finish!: (value: typeof receipt.run) => void;
  vi.spyOn(api, "retrySourceRunSave").mockReturnValue(new Promise(resolve => { finish = resolve; }));
  render(<SourceScanPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Recheck finding" }));
  fireEvent.click(await screen.findByRole("button", { name: "Retry recheck save" }));
  let replacement!: number;
  await act(async () => {
    releaseScan(useScanWorkStore.getState().active!.id);
    replacement = acquireScan("project", "/other", "Scanning source")!;
  });
  await act(async () => finish(receipt.run));
  expect(compare).not.toHaveBeenCalled();
  expect(useScanWorkStore.getState().active?.id).toBe(replacement);
  expect(screen.getByRole("button", { name: "Retry recheck save" })).toBeDisabled();
  expect(screen.queryByText(/No longer detected in the covered file/)).not.toBeInTheDocument();
});

test("unsaved recheck remains recoverable after a failed history load keeps its original visible", async () => {
  vi.spyOn(api, "recheckSourceRun").mockResolvedValue(unsavedReceipt);
  const save = vi.spyOn(api, "retrySourceRunSave").mockResolvedValue(receipt.run);
  const compare = vi.spyOn(api, "compareSourceRuns").mockResolvedValue([{ ...finding, diffStatus: "resolved", resolvedByRunId: "next" }]);
  vi.mocked(api.listSourceRuns).mockResolvedValue([{ runId: "historic", projectId: original.projectId, status: "completed", startedAt: original.startedAt, completedAt: original.completedAt, totalFindings: 99, newFindings: 99, resolvedFindings: 0 }]);
  vi.mocked(api.loadSourceRun).mockImplementation(async id => {
    if (id === "historic") throw new Error("Historical run unavailable");
    return original;
  });
  render(<SourceScanPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Recheck finding" }));
  await screen.findByRole("button", { name: "Retry recheck save" });
  fireEvent.click(screen.getByRole("button", { name: /99 findings/ }));
  await screen.findByText("Historical run unavailable");
  expect(screen.getByText("eval(input)", { selector: "pre" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Retry recheck save" }));
  await waitFor(() => expect(save).toHaveBeenCalledWith("recheck-retry"));
  await screen.findByText(/No longer detected in the covered file/);
  expect(compare).toHaveBeenCalledWith("next", "s", true);
});
