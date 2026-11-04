import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { Dashboard } from "../../pages/Dashboard";
import { DependencyHomeSummary } from "./DependencyHomeSummary";
import { api } from "../../lib/api";
import { useAppStore } from "../../lib/stores";
import { useScanWorkStore } from "./coordinator";
import { dependencyResult, projectContext, projectSettings } from "../../../tests/fixtures/projectHome";
import type { CanonicalProjectionMetadata, CanonicalRun, DependencyScanResult, Vulnerability } from "../../lib/types";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

function receipt(id = "saved-a", targetLabel = "/a", state: CanonicalRun["state"] = "completed"): CanonicalRun {
  return { id, targetLabel, kind: "dependencies", state, attempt: 1, createdAtMs: 100, updatedAtMs: 200,
    engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] };
}
function metadata(id = "saved-a", path = "/a", total = 120): CanonicalProjectionMetadata<DependencyScanResult> {
  const result = dependencyResult(path);
  return { kind: "pagedProjection", projectionKind: "dependencies", projection: {
    ...result, summary: { ...result.summary, runId: id, packagesFound: 543, packagesQueried: 543, vulnerabilitiesFound: total },
  }, sections: { dependencies: 543, vulnerabilities: total } };
}
const advisory: Vulnerability = {
  id: "CVE-fixture", aliases: [], summary: "Inert advisory", details: "Fixture only", severity: "high",
  cvssScore: null, epss: null, epssPercentile: null, knownExploited: false, ransomware: false, publicExploit: false,
  directUsage: { referenced: null, referencedFiles: 0, exampleFile: null }, ecosystem: "npm", packageName: "fixture",
  installedVersion: "1", fixedVersions: [], affectedRange: null, references: [], published: null, modified: null, lockfile: "package-lock.json",
};
beforeEach(() => {
  useAppStore.setState({ selectedProject: "/a", activeProject: null, projectHandoff: null, page: "dashboard", settings: projectSettings });
  useScanWorkStore.setState({ active: null, check: null });
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([]);
  vi.spyOn(api, "listSourceRuns").mockResolvedValue([]);
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([receipt(), receipt("saved-b", "/b")]);
  vi.spyOn(api, "inspectSourceProject").mockImplementation(async path => projectContext(path));
  vi.spyOn(api, "setActiveProject").mockResolvedValue();
  vi.spyOn(api, "loadCanonicalProjectionMetadata").mockImplementation(async id => metadata(id, id === "saved-b" ? "/b" : "/a"));
  vi.spyOn(api, "loadCanonicalProjectionPage").mockImplementation(async (_id, _section, query = {}) => ({
    items: [{ ...advisory, severity: query.severity ?? "high" }], total: 120,
    filteredTotal: query.severity === "critical" ? 7 : 13, offset: 0, limit: 1,
  }));
});

test("home shows full saved severity counts using bounded queries for only the selected project", async () => {
  const full = vi.spyOn(api, "loadCanonicalProjection");
  render(<Dashboard />);
  expect(await screen.findByText(/120 vulnerabilities · 7 critical · 13 high/)).toBeInTheDocument();
  expect(screen.getByText("Advisory coverage: complete · 543 packages")).toBeInTheDocument();
  expect(api.loadCanonicalProjectionMetadata).toHaveBeenCalledExactlyOnceWith("saved-a");
  expect(api.loadCanonicalProjectionPage).toHaveBeenCalledWith("saved-a", "vulnerabilities", { severity: "critical", offset: 0, limit: 1 });
  expect(api.loadCanonicalProjectionPage).toHaveBeenCalledWith("saved-a", "vulnerabilities", { severity: "high", offset: 0, limit: 1 });
  expect(full).not.toHaveBeenCalled();
});

test.each([undefined, "unknown"] as const)("zero observed findings retain unknown advisory coverage (%s)", async coverage => {
  const value = metadata("saved-a", "/a", 0);
  value.projection.summary.advisoryCoverage = coverage;
  vi.mocked(api.loadCanonicalProjectionMetadata).mockResolvedValue(value);
  render(<Dashboard />);
  expect(await screen.findByText(/0 vulnerabilities · 0 critical · 0 high/)).toBeInTheDocument();
  expect(screen.getByText("Advisory coverage: unknown · 543 packages")).toBeInTheDocument();
  expect(screen.queryByText(/project is safe|project is clean/i)).not.toBeInTheDocument();
  expect(api.loadCanonicalProjectionPage).not.toHaveBeenCalled();
});

test("a failed latest attempt keeps counts explicitly tied to the last completed receipt", async () => {
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([
    { ...receipt("failed-a", "/a", "failed"), createdAtMs: 300, updatedAtMs: 300 }, receipt(),
  ]);
  render(<Dashboard />);
  expect(await screen.findByText(/120 vulnerabilities · 7 critical · 13 high/)).toBeInTheDocument();
  expect(screen.getByText("Dependencies: failed")).toBeInTheDocument();
  expect(screen.getByText("Counts reflect the last completed dependency run.")).toBeInTheDocument();
  expect(api.loadCanonicalProjectionMetadata).toHaveBeenCalledExactlyOnceWith("saved-a");
});

test("home summarizes the same last-completed run as dependency results when scans finish out of order", async () => {
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([
    { ...receipt("slow"), createdAtMs: 100, updatedAtMs: 400 },
    { ...receipt("fast"), createdAtMs: 200, updatedAtMs: 300 },
    { ...receipt("failed", "/a", "failed"), createdAtMs: 500, updatedAtMs: 600 },
  ]);
  vi.mocked(api.loadCanonicalProjectionMetadata).mockImplementation(async id => metadata(id, "/a", id === "slow" ? 8 : 0));
  vi.mocked(api.loadCanonicalProjectionPage).mockImplementation(async (_id, _section, query = {}) => ({
    items: query.severity === "critical" ? [{ ...advisory, severity: "critical" }] : [],
    total: 8, filteredTotal: query.severity === "critical" ? 8 : 0, offset: 0, limit: 1,
  }));
  render(<Dashboard />);
  expect(await screen.findByText(/8 vulnerabilities · 8 critical · 0 high/)).toBeInTheDocument();
  expect(screen.getByText("Dependencies: failed")).toBeInTheDocument();
  expect(api.loadCanonicalProjectionMetadata).toHaveBeenCalledExactlyOnceWith("slow");
});

test.each(["run", "target", "kind", "count"])("invalid %s metadata remains unknown and does not load severity rows", async invalid => {
  const value = metadata();
  if (invalid === "run") value.projection.summary.runId = "another-run";
  if (invalid === "target") value.projection.summary.path = "/another-project";
  if (invalid === "kind") value.projectionKind = "binary";
  if (invalid === "count") value.sections.vulnerabilities = -1;
  vi.mocked(api.loadCanonicalProjectionMetadata).mockResolvedValue(value);
  render(<Dashboard />);
  expect(await screen.findByText(/Saved dependency summary unavailable/)).toBeInTheDocument();
  expect(screen.getByText("Dependency findings: unknown.")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Check project" })).toBeEnabled();
  expect(api.loadCanonicalProjectionPage).not.toHaveBeenCalled();
});

test("a failed severity query is retryable without leaving home or inventing zero counts", async () => {
  vi.mocked(api.loadCanonicalProjectionPage).mockRejectedValueOnce(new Error("Saved count temporarily unavailable"));
  render(<Dashboard />);
  expect(await screen.findByText(/Saved dependency summary unavailable/)).toHaveTextContent("Saved count temporarily unavailable");
  expect(screen.queryByText(/0 vulnerabilities/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Retry dependency summary" }));
  expect(await screen.findByText(/120 vulnerabilities · 7 critical · 13 high/)).toBeInTheDocument();
});

test("an older A response cannot replace the summary after switching A to B to A", async () => {
  let finish!: (value: CanonicalProjectionMetadata<DependencyScanResult>) => void;
  vi.mocked(api.loadCanonicalProjectionMetadata).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  render(<Dashboard />);
  await waitFor(() => expect(finish).toBeDefined());
  await act(async () => useAppStore.getState().setSelectedProject("/b"));
  await screen.findByText(/120 vulnerabilities · 7 critical · 13 high/);
  vi.mocked(api.loadCanonicalProjectionMetadata).mockResolvedValue(metadata("saved-a", "/a", 0));
  await act(async () => useAppStore.getState().setSelectedProject("/a"));
  await screen.findByText(/0 vulnerabilities · 0 critical · 0 high/);
  await act(async () => finish(metadata("saved-a", "/a", 999)));
  expect(screen.getByText(/0 vulnerabilities · 0 critical · 0 high/)).toBeInTheDocument();
  expect(screen.queryByText(/999 vulnerabilities/)).not.toBeInTheDocument();
});

test("refreshing the same receipt recovers missing metadata", async () => {
  vi.mocked(api.loadCanonicalProjectionMetadata).mockRejectedValueOnce(new Error("Saved receipt missing"));
  render(<Dashboard />);
  await screen.findByText(/Saved receipt missing/);
  fireEvent.click(screen.getByRole("button", { name: "Refresh projects" }));
  expect(await screen.findByText(/120 vulnerabilities · 7 critical · 13 high/)).toBeInTheDocument();
});

test("a late response cannot overwrite a refreshed summary of the same receipt", async () => {
  let finish!: (value: CanonicalProjectionMetadata<DependencyScanResult>) => void;
  vi.mocked(api.loadCanonicalProjectionMetadata).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const run = receipt();
  const { rerender } = render(<DependencyHomeSummary run={run} revision={0} refreshing={false} />);
  await waitFor(() => expect(finish).toBeDefined());
  vi.mocked(api.loadCanonicalProjectionMetadata).mockResolvedValue(metadata("saved-a", "/a", 0));
  rerender(<DependencyHomeSummary run={run} revision={1} refreshing={false} />);
  await screen.findByText(/0 vulnerabilities · 0 critical · 0 high/);
  await act(async () => finish(metadata("saved-a", "/a", 120)));
  expect(screen.getByText(/0 vulnerabilities · 0 critical · 0 high/)).toBeInTheDocument();
});

test("failed attempts without a completed receipt never request or display a saved summary", async () => {
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([receipt("failed-a", "/a", "failed")]);
  render(<Dashboard />);
  await screen.findByRole("button", { name: "Check project" });
  expect(screen.getByText("No completed dependency scan is available.")).toBeInTheDocument();
  expect(api.loadCanonicalProjectionMetadata).not.toHaveBeenCalled();
});
