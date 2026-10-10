import { canonicalMetadata, canonicalPage, sourceMetadata, sourcePage } from "../../tests/fixtures/pagedResults";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { useAppStore } from "../lib/stores";
import { reconcileBackendWork, useScanWorkStore } from "../features/project-home/coordinator";
import { SourceScanPage } from "./SourceScan";
import { DepsScanPage } from "./DepsScan";
import { BinaryScanPage } from "./BinaryScan";
import { ImageScanPage } from "./ImageScanPage";
import { HistoryScanPage } from "./HistoryScan";
import { dependencyResult, projectContext, projectSettings, sourceResult } from "../../tests/fixtures/projectHome";
import type { BinaryScanResult, CanonicalRun, HistoryScanResult, ImageScanOutcome } from "../lib/types";

const events = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => { events.set(name, handler); return () => events.delete(name); }) }));
vi.mock("@tauri-apps/api/webview", () => ({ getCurrentWebview: () => ({ onDragDropEvent: async () => () => {} }) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const target = "/evidence/project";
const observed = Date.parse("2026-09-07T00:01:00Z");
const binary: BinaryScanResult = { target, components: [], summary: { components: 0, vulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, databaseLastUpdated: null, durationMs: 1, scanners: ["native"] };
let runs: CanonicalRun[];
let projection: unknown;
let source = sourceResult(target);
const canonical = (kind: CanonicalRun["kind"], overrides: Partial<CanonicalRun> = {}): CanonicalRun => ({ id: `${kind}-receipt`, kind, targetLabel: target, state: "completed", attempt: 1, createdAtMs: observed - 1000, updatedAtMs: observed, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [], ...overrides });

beforeEach(() => {
  events.clear();
  runs = [];
  projection = null;
  source = sourceResult(target);
  useAppStore.setState({ activeProject: target, selectedProject: null, projectHandoff: null, exportHandoff: null, pageStatus: {}, settings: projectSettings, settingsLoadError: false });
  useScanWorkStore.setState({ active: null, check: null, backend: { active: null, recent: [] }, lastTargets: {}, recoveryError: null });
  vi.mocked(invoke).mockImplementation(async (command, args) => {
    switch (command) {
      case "list_canonical_runs": return runs;
      case "load_canonical_projection": return projection;
      case "load_canonical_projection_metadata": return canonicalMetadata(projection);
      case "load_canonical_projection_page": { const a = args as any; return canonicalPage(projection, a.section, a.query); }
      case "inspect_source_project": return { ...projectContext(target), lastCompletedRunId: source.runId };
      case "list_source_projects": case "list_source_runs": return [];
      case "load_source_run": return source;
      case "load_source_run_metadata": return sourceMetadata(source);
      case "load_source_run_page": return sourcePage(source, (args as any).query);
      case "set_active_project": return undefined;
      case "inspect_source_git": throw new Error("No Git context");
      case "scan_work_status": return { active: null, recent: [] };
      case "binary_tool_status": {
        const unavailable = { available: false, program: null, version: null, source: null, message: null };
        return { native: { ...unavailable, available: true, program: "native" }, cveBinTool: unavailable, grype: unavailable, docker: unavailable, runtime: "auto", canScan: true };
      }
      default: throw new Error(`Unexpected transport command: ${command}`);
    }
  });
});

// A completed operation must never hide skipped files or an unsaved receipt behind its zero count.
test("source evidence keeps skipped scope and save recovery visible with no recorded findings", async () => {
  source.persistence = { status: "notSaved", retryToken: "save-token" };
  source.summary.filesSkipped = 2;
  source.summary.coverageWarnings = ["Could not read private.ts"];
  render(<SourceScanPage />);
  const summary = await screen.findByRole("region", { name: "Source evidence summary" });
  expect(summary).toHaveTextContent("Operation completed");
  expect(summary).toHaveTextContent("Not saved");
  expect(summary).toHaveTextContent("0 findings recorded");
  expect(summary).toHaveTextContent("1 file scanned · 2 skipped");
  const warning = within(summary).getByText("Could not read private.ts");
  expect(warning.closest("[hidden]")).toBeNull();
  expect(summary).toHaveTextContent("2026-09-07T00:01:00.000Z");
  expect(summary).toHaveTextContent(/Retry saving/);
});

// Legacy receipts without advisory coverage must stay unknown even when the operation completed.
test("dependency evidence identifies the saved receipt and unknown offline advisory coverage", async () => {
  runs = [canonical("dependencies")];
  const dependency = dependencyResult(target);
  dependency.summary.advisoryCoverage = undefined;
  dependency.summary.advisorySource = "offline-cache";
  dependency.summary.advisoryNotes = ["Only exact saved queries were available"];
  projection = dependency;
  render(<DepsScanPage />);
  const summary = await screen.findByRole("region", { name: "Dependency evidence summary" });
  expect(summary).toHaveTextContent("Advisory coverage unknown");
  expect(summary).toHaveTextContent("1 of 1 packages queried");
  expect(summary).toHaveTextContent("offline-cache");
  expect(within(summary).getByText("Only exact saved queries were available").closest("[hidden]")).toBeNull();
  expect(summary).toHaveTextContent("2026-09-07T00:01:00.000Z");
  const disclosure = within(summary).getByRole("button", { name: "Evidence details" });
  expect(disclosure).toHaveAttribute("aria-expanded", "false");
  disclosure.focus();
  await userEvent.keyboard("{Enter}");
  expect(disclosure).toHaveAttribute("aria-expanded", "true");
  expect(within(summary).getByText("dependencies-receipt")).toBeVisible();
  await userEvent.keyboard(" ");
  expect(disclosure).toHaveAttribute("aria-expanded", "false");
});

// Saved canonical warnings and semantic limits must survive reloading, not be replaced by today's tool switches.
test("binary evidence reports saved scanner scope and semantic candidates without inventing full coverage", async () => {
  runs = [canonical("binary", { warnings: [{ code: "lookup", message: "CVE lookup capped at 20 components" }] })];
  projection = { ...binary, semanticAnalysis: { architecture: "arm64", functionsAnalyzed: 2, callEdges: 1, unresolvedEdges: 3, findings: [{ ruleId: "candidate", functionAddress: 12, confidence: 0.9, evidence: [], limitations: [] }], limitations: ["Indirect calls were not resolved"] } };
  render(<BinaryScanPage />);
  const summary = await screen.findByRole("region", { name: "Binary evidence summary" });
  expect(summary).toHaveTextContent("0 CVEs recorded · 1 semantic candidate");
  expect(summary).toHaveTextContent("native");
  expect(summary).toHaveTextContent("Advisory coverage unknown");
  expect(within(summary).getByText("CVE lookup capped at 20 components").closest("[hidden]")).toBeNull();
  expect(within(summary).getByText("Indirect calls were not resolved").closest("[hidden]")).toBeNull();
});

// The newest failed attempt must remain separate from the completed receipt used for export.
test("image evidence separates the latest failed attempt and exports the displayed older receipt by keyboard", async () => {
  runs = [canonical("image", { id: "image-failure", state: "failed", updatedAtMs: observed + 1000, warnings: [{ code: "registry", message: "Registry request failed" }] }), canonical("image")];
  projection = { runId: "image-receipt", result: binary, notes: ["NVD matching unavailable offline"], imageDigest: "sha256:image-identity", layers: [], offline: true } satisfies ImageScanOutcome;
  render(<ImageScanPage />);
  const summary = await screen.findByRole("region", { name: "Image evidence summary" });
  expect(summary).toHaveTextContent("Latest attempt failed");
  expect(summary).toHaveTextContent("Saved receipt · completed");
  expect(summary).toHaveTextContent("2026-09-07T00:01:00.000Z");
  expect(summary).toHaveTextContent("Offline advisories");
  expect(within(summary).getByText("NVD matching unavailable offline").closest("[hidden]")).toBeNull();
  expect(within(summary).getByText("Registry request failed").closest("[hidden]")).toBeNull();
  const exportButton = within(summary).getByRole("button", { name: "Open Export Center" });
  exportButton.focus();
  await userEvent.keyboard("{Enter}");
  expect(useAppStore.getState().exportHandoff).toEqual({ runId: "image-receipt" });
  expect(within(summary).getByText("sha256:image-identity")).not.toBeVisible();
});

// Truncation and skipped history cannot read as clean when zero findings were retained.
test("history evidence presents partial zero findings with ref scope and a rerun action", async () => {
  runs = [canonical("history", { state: "incomplete" })];
  projection = { runId: "history-receipt", findings: [], blobsScanned: 10, blobsSkipped: 4, truncated: true, limitNote: "Byte budget reached", validation: null } satisfies HistoryScanResult;
  render(<HistoryScanPage />);
  const summary = await screen.findByRole("region", { name: "History evidence summary" });
  expect(summary).toHaveTextContent("Receipt incomplete");
  expect(summary).toHaveTextContent("0 findings recorded");
  expect(summary).toHaveTextContent("10 blobs scanned · 4 skipped");
  expect(summary).toHaveTextContent(/ref-reachable/i);
  expect(within(summary).getByText("Byte budget reached").closest("[hidden]")).toBeNull();
  expect(summary).toHaveTextContent(/Rerun/);
  expect(useAppStore.getState().pageStatus["history-scan"]?.label).not.toMatch(/clean/i);
});

// An old receipt must not acquire today's timestamps or silently treat missing state as completed.
test("legacy history execution records completion separately from unknown receipt state and identity", async () => {
  const scanned: HistoryScanResult = { findings: [], blobsScanned: 3, blobsSkipped: 0, truncated: false, limitNote: null, validation: null };
  const original = vi.mocked(invoke).getMockImplementation()!;
  vi.mocked(invoke).mockImplementation(async (command, args) => command === "scan_history_secrets" ? scanned : original(command, args));
  render(<HistoryScanPage />);
  fireEvent.click(screen.getByRole("button", { name: "Scan history" }));
  const summary = await screen.findByRole("region", { name: "History evidence summary" });
  expect(summary).toHaveTextContent("Operation completed");
  expect(summary).toHaveTextContent("Save status unknown · state unknown");
  expect(within(summary).getByRole("status")).not.toHaveClass("text-warning");
  expect(summary).toHaveTextContent("Recorded time unknown");
  expect(useAppStore.getState().pageStatus["history-scan"]?.label).not.toMatch(/clean/i);
});

// A cancelled replacement may retain a prior receipt but must not label the replacement completed.
test("binary cancellation retains the previous receipt while identifying the cancelled operation", async () => {
  runs = [canonical("binary")];
  projection = binary;
  let complete!: (result: BinaryScanResult) => void;
  const original = vi.mocked(invoke).getMockImplementation()!;
  vi.mocked(invoke).mockImplementation(async (command, args) => command === "scan_binaries" ? new Promise(resolve => { complete = resolve; }) : command === "cancel_scan_work" ? true : original(command, args));
  render(<BinaryScanPage />);
  const summary = await screen.findByRole("region", { name: "Binary evidence summary" });
  fireEvent.click(screen.getByRole("button", { name: "Run scan" }));
  await waitFor(() => expect(summary).toHaveTextContent("Operation running"));
  expect(summary).toHaveTextContent("Previous evidence is shown");
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  await act(async () => complete({ ...binary, summary: { ...binary.summary, components: 99 } }));
  expect(summary).toHaveTextContent("Latest operation cancelled");
  expect(summary).toHaveTextContent("Saved receipt · completed");
  expect(summary).not.toHaveTextContent("99 components");
});

// A successful retry must replace the operation state as well as the displayed findings.
test.each(["failed", "cancelled"])("a dependency retry clears a previous %s operation", async mode => {
  runs = [canonical("dependencies")];
  projection = dependencyResult(target);
  let resolve!: (value: ReturnType<typeof dependencyResult>) => void;
  let launches = 0;
  const replacement = dependencyResult(target);
  replacement.summary.packagesFound = 2;
  replacement.summary.packagesQueried = 2;
  const original = vi.mocked(invoke).getMockImplementation()!;
  vi.mocked(invoke).mockImplementation(async (command, args) => {
    if (command === "scan_dependencies") {
      launches++;
      if (launches > 1) return replacement;
      if (mode === "failed") throw new Error("Provider unavailable");
      return new Promise(done => { resolve = done; });
    }
    return command === "cancel_scan_work" ? true : original(command, args);
  });
  render(<DepsScanPage />);
  const summary = await screen.findByRole("region", { name: "Dependency evidence summary" });
  fireEvent.click(screen.getByRole("button", { name: "Check dependencies" }));
  if (mode === "cancelled") {
    await screen.findByRole("button", { name: "Cancel" });
    await waitFor(() => expect(resolve).toBeDefined());
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await act(async () => resolve(dependencyResult(target)));
  }
  await waitFor(() => expect(summary).toHaveTextContent(`Latest operation ${mode}`));
  fireEvent.click(screen.getByRole("button", { name: "Check dependencies" }));
  await waitFor(() => expect(summary).toHaveTextContent("2 of 2 packages queried"));
  expect(within(summary).getByRole("status")).toHaveTextContent("Operation completed");
  expect(summary).not.toHaveTextContent(`Latest operation ${mode}`);
});

// A newer failed attempt's reason must not disappear when a completed prior receipt is loaded.
test.each(["binary", "dependencies"] as const)("%s evidence retains the latest failed attempt warning beside prior receipt", async kind => {
  runs = [canonical(kind, { id: "latest-failed", state: "failed", updatedAtMs: observed + 1000, warnings: [{ code: "provider", message: "Latest provider request timed out" }] }), canonical(kind)];
  projection = kind === "binary" ? binary : dependencyResult(target);
  render(kind === "binary" ? <BinaryScanPage /> : <DepsScanPage />);
  const summary = await screen.findByRole("region", { name: `${kind === "binary" ? "Binary" : "Dependency"} evidence summary` });
  expect(summary).toHaveTextContent("Latest attempt failed");
  expect(summary).toHaveTextContent("Saved receipt · completed");
  expect(within(summary).getByText("Latest provider request timed out").closest("[hidden]")).toBeNull();
});

// An incomplete retained source receipt must not mark every lifecycle stage complete.
test("an idle incomplete source receipt retains its status without implying live progress or completion", async () => {
  source.status = "incomplete";
  render(<SourceScanPage />);
  const receipt = await screen.findByRole("region", { name: "Source evidence summary" });
  expect(receipt).toHaveTextContent(/incomplete/i);
  expect(screen.queryByRole("region", { name: "Scan progress" })).not.toBeInTheDocument();
  expect(receipt).not.toHaveTextContent("Operation completed");
});

// A replacement must not relabel an incomplete prior receipt as a completed result.
test("a running source replacement does not call the prior incomplete receipt completed", async () => {
  source.status = "incomplete";
  let finish!: (value: ReturnType<typeof sourceResult>) => void;
  const original = vi.mocked(invoke).getMockImplementation()!;
  vi.mocked(invoke).mockImplementation(async (command, args) => command === "scan_project" ? new Promise(resolve => { finish = resolve; }) : original(command, args));
  render(<SourceScanPage />);
  await screen.findByRole("region", { name: "Source evidence summary" });
  await waitFor(() => expect(screen.getByRole("button", { name: "Run scan" })).toBeEnabled());
  fireEvent.click(screen.getByRole("button", { name: "Run scan" }));
  await waitFor(() => expect(finish).toBeDefined());
  const lifecycle = screen.getByRole("region", { name: "Scan progress" });
  expect(lifecycle).not.toHaveTextContent("A previous completed result remains available");
  expect(screen.getByRole("region", { name: "Source evidence summary" })).toHaveTextContent("Previous evidence is shown");
  await act(async () => finish(sourceResult(target)));
});

// A zero history count describes an observation, including when the final ref snapshot is unavailable.
test("empty history with unknown refs describes recorded absence rather than claiming no secrets exist", async () => {
  runs = [canonical("history")];
  projection = { runId: "history-receipt", findings: [], blobsScanned: 10, blobsSkipped: 0, truncated: false, limitNote: null, validation: null } satisfies HistoryScanResult;
  render(<HistoryScanPage />);
  await screen.findByRole("region", { name: "History evidence summary" });
  expect(screen.getByText(/No findings recorded — 10 blobs scanned/)).toBeInTheDocument();
  expect(screen.queryByText(/No secrets in history/)).not.toBeInTheDocument();
});

// A replacement attempt's notes must remain distinct from evidence produced by an older receipt.
test("binary replacement warnings are labelled separately from the displayed prior receipt", async () => {
  runs = [canonical("binary", { warnings: [{ code: "prior", message: "Prior scan skipped one archive" }] })];
  projection = binary;
  let complete!: (value: BinaryScanResult) => void;
  const original = vi.mocked(invoke).getMockImplementation()!;
  vi.mocked(invoke).mockImplementation(async (command, args) => command === "scan_binaries" ? new Promise(resolve => { complete = resolve; }) : command === "cancel_scan_work" ? true : original(command, args));
  render(<BinaryScanPage />);
  const summary = await screen.findByRole("region", { name: "Binary evidence summary" });
  fireEvent.click(screen.getByRole("button", { name: "Run scan" }));
  await waitFor(() => expect(complete).toBeDefined());
  await act(async () => events.get("binscan://note")?.({ payload: { operationId: useScanWorkStore.getState().active!.operationId, message: "Replacement lookup unavailable" } }));
  expect(within(summary).getByText("Replacement lookup unavailable").closest('[aria-label="Latest attempt warnings"]')).not.toBeNull();
  expect(within(summary).getByRole("list", { name: "Evidence limits" })).not.toHaveTextContent("Replacement lookup unavailable");
  expect(within(summary).getByRole("list", { name: "Evidence limits" })).toHaveTextContent("Prior scan skipped one archive");
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  await act(async () => complete(binary));
  expect(within(summary).getByText("Replacement lookup unavailable").closest('[aria-label="Latest attempt warnings"]')).not.toBeNull();
});

// A newly recovered failed attempt must override the earlier successful legacy operation fallback.
test("history recovery replaces the earlier completed operation with the newest failed attempt", async () => {
  const scanned: HistoryScanResult = { runId: "history-receipt", state: "completed", findings: [], blobsScanned: 10, blobsSkipped: 0, truncated: false, limitNote: null, validation: null };
  const original = vi.mocked(invoke).getMockImplementation()!;
  vi.mocked(invoke).mockImplementation(async (command, args) => command === "scan_history_secrets" ? scanned : original(command, args));
  render(<HistoryScanPage />);
  fireEvent.click(screen.getByRole("button", { name: "Scan history" }));
  const summary = await screen.findByRole("region", { name: "History evidence summary" });
  expect(within(summary).getByRole("status")).toHaveTextContent("Operation completed");
  runs = [canonical("history", { id: "failed-newer", state: "failed", updatedAtMs: observed + 1000, warnings: [{ code: "git", message: "Git object unavailable" }] }), canonical("history")];
  projection = scanned;
  await act(async () => reconcileBackendWork({ active: null, recent: [{ operationId: "recovered-failure", kind: "history", target, status: "failed", runId: "failed-newer", startedAtMs: observed, updatedAtMs: observed + 1000 }] }));
  await waitFor(() => expect(within(summary).getByRole("status")).toHaveTextContent("Latest attempt failed"));
  expect(summary).toHaveTextContent("Saved receipt · completed");
  expect(within(summary).getByText("Git object unavailable")).toBeVisible();
});
