import { canonicalMetadata, canonicalPage } from "../../tests/fixtures/pagedResults";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useAppStore } from "../lib/stores";
import type { BinaryScannersStatus, BinaryScanResult, BinaryVulnerability, CanonicalRun, DependencyScanResult, Vulnerability } from "../lib/types";
import { DepsScanPage } from "./DepsScan";
import { BinaryScanPage } from "./BinaryScan";

const backend = vi.hoisted(() => ({ listCanonicalRuns: vi.fn(), loadCanonicalProjection: vi.fn(), loadCanonicalProjectionMetadata: vi.fn(), loadCanonicalProjectionPage: vi.fn(), binaryToolStatus: vi.fn() }));
vi.mock("../lib/api", () => ({ api: backend }));
vi.mock("../lib/events", () => ({ listen: async () => () => {} }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const target = "/tmp/list-pagination-fixture";
function run(kind: CanonicalRun["kind"]): CanonicalRun {
  return { id: "saved", kind, targetLabel: target, state: "completed", attempt: 1,
    createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] };
}
function vulnerability(index: number): Vulnerability {
  return { id: `GHSA-${index}`, aliases: [], summary: `Advisory ${index}`, details: "details", severity: "high",
    cvssScore: null, epss: null, epssPercentile: null, knownExploited: false, ransomware: false,
    publicExploit: false, directUsage: { referenced: null, referencedFiles: 0, exampleFile: null },
    ecosystem: "npm", packageName: `package-${index}`, installedVersion: "1.0.0", fixedVersions: [],
    affectedRange: null, references: [], published: null, modified: null, lockfile: `${target}/package-lock.json` };
}
function binaryVulnerability(index: number): BinaryVulnerability {
  return { cveId: `CVE-test-${index}`, severity: index === 9_999 ? "critical" : "high", score: null,
    cvssVersion: null, cvssVector: null, source: "fixture", remarks: null, epssProbability: null,
    epssPercentile: null, knownExploited: false, ransomware: false, publicExploit: false, fixedIn: null };
}
const tools: BinaryScannersStatus = {
  native: { available: true, program: "native", version: null, source: null, message: "built in" },
  cveBinTool: { available: false, program: null, version: null, source: null, message: null },
  grype: { available: false, program: null, version: null, source: null, message: null },
  docker: { available: false, program: null, version: null, source: null, message: null }, runtime: "auto", canScan: true,
};
beforeEach(() => {
  vi.clearAllMocks();
  useAppStore.setState({ activeProject: target, selectedProject: null, pageStatus: {} });
  backend.binaryToolStatus.mockResolvedValue(tools);
  backend.loadCanonicalProjectionMetadata.mockImplementation(async id => canonicalMetadata(await backend.loadCanonicalProjection.getMockImplementation()?.(id)));
  backend.loadCanonicalProjectionPage.mockImplementation(async (id, section, query) => canonicalPage(await backend.loadCanonicalProjection.getMockImplementation()?.(id), section, query));
});

describe("large result pages", () => {
  it("bounds 10,000 dependency advisories and upgrade groups, retaining identity after page navigation and search", async () => {
    const vulnerabilities = Array.from({ length: 10_000 }, (_, index) => vulnerability(index));
    const result: DependencyScanResult = { summary: { path: target, lockfilesFound: [`${target}/package-lock.json`],
      packagesFound: 10_000, packagesQueried: 10_000, vulnerabilitiesFound: 10_000, durationMs: 1, advisoryCoverage: "complete" },
      dependencies: [], vulnerabilities };
    backend.listCanonicalRuns.mockResolvedValue([run("dependencies")]);
    backend.loadCanonicalProjection.mockResolvedValue(result);
    const started = performance.now();
    render(<DepsScanPage />);
    const table = await screen.findByText("Vulnerable packages and their advisory risk").then(caption => caption.closest("table")!);
    const renderMs = performance.now() - started;
    await waitFor(() => expect(table.querySelectorAll("tbody tr")).toHaveLength(50));
    expect(backend.loadCanonicalProjection).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Load complete upgrade decisions" }));
    await screen.findByText("Upgrade groups by installation and update entry point");
    expect(screen.getByText("Upgrade groups by installation and update entry point").closest("table")!.querySelectorAll("tbody tr")).toHaveLength(50);
    const moved = performance.now();
    fireEvent.click(screen.getByRole("button", { name: "Last page of dependency advisories" }));
    const lastPageMs = performance.now() - moved;
    const row = await within(table).findByRole("row", { name: "Select package-9999 advisory GHSA-9999" });
    fireEvent.keyDown(row, { key: "Enter" });
    expect(row).toHaveAttribute("aria-current", "true");
    fireEvent.click(screen.getByRole("button", { name: "First page of dependency advisories" }));
    await within(table).findByRole("row", { name: "Select package-0 advisory GHSA-0" });
    fireEvent.click(screen.getByRole("button", { name: "Last page of dependency advisories" }));
    expect(await within(table).findByRole("row", { name: "Select package-9999 advisory GHSA-9999" })).toHaveAttribute("aria-current", "true");
    fireEvent.change(screen.getByRole("textbox", { name: "Search dependency vulnerabilities" }), { target: { value: "package-9999" } });
    await waitFor(() => expect(table.querySelectorAll("tbody tr")).toHaveLength(1));
    expect(await within(table).findByRole("row", { name: "Select package-9999 advisory GHSA-9999" })).toHaveAttribute("aria-current", "true");
    console.info("result-list-measurement", JSON.stringify({ list: "dependencies", records: 10_000, renderedRows: 50, renderMs, lastPageMs, environment: "jsdom" }));
  });

  it("bounds 10,000 binary components and resets the last page after a severity filter", async () => {
    const result: BinaryScanResult = { target, components: Array.from({ length: 10_000 }, (_, index) => ({
      vendor: "fixture", product: `component-${index}`, version: "1.0", paths: [], detectedBy: ["native"], vulnerabilities: [binaryVulnerability(index)],
    })), summary: { components: 10_000, vulnerabilities: 10_000, critical: 1, high: 9_999, medium: 0, low: 0, unknown: 0 },
      databaseLastUpdated: null, durationMs: 1, scanners: ["native"] };
    backend.listCanonicalRuns.mockResolvedValue([run("binary")]);
    backend.loadCanonicalProjection.mockResolvedValue(result);
    const started = performance.now();
    render(<BinaryScanPage />);
    await screen.findByText("component-0");
    const renderMs = performance.now() - started;
    const list = screen.queryByRole("list", { name: "Binary components" }) ?? screen.getByText("component-0").closest("li")!.parentElement!;
    expect(backend.loadCanonicalProjection).not.toHaveBeenCalled();
    expect(list.children).toHaveLength(50);
    expect(list).toHaveAttribute("aria-label", "Binary components");
    const moved = performance.now();
    fireEvent.click(screen.getByRole("button", { name: "Last page of binary components" }));
    const lastPageMs = performance.now() - moved;
    expect(await screen.findByText("component-9999")).toBeInTheDocument();
    expect(list.children).toHaveLength(50);
    fireEvent.change(screen.getByRole("combobox", { name: "Minimum severity shown" }), { target: { value: "critical" } });
    await waitFor(() => expect(list.children).toHaveLength(1));
    expect(await screen.findByText("component-9999")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next page of binary components" })).toBeDisabled();
    console.info("result-list-measurement", JSON.stringify({ list: "binary", records: 10_000, renderedRows: 50, renderMs, lastPageMs, environment: "jsdom" }));
  });

  it("also bounds a single binary component with 10,000 CVEs and 10,000 semantic findings", async () => {
    const result: BinaryScanResult = { target, components: [{ vendor: "fixture", product: "crowded", version: "1.0", paths: [],
      detectedBy: ["native"], vulnerabilities: Array.from({ length: 10_000 }, (_, index) => binaryVulnerability(index)) }],
      summary: { components: 1, vulnerabilities: 10_000, critical: 1, high: 9_999, medium: 0, low: 0, unknown: 0 }, databaseLastUpdated: null, durationMs: 1, scanners: ["native"],
      semanticAnalysis: { architecture: "test", functionsAnalyzed: 10_000, callEdges: 0, unresolvedEdges: 0, limitations: [],
        findings: Array.from({ length: 10_000 }, (_, index) => ({ ruleId: `sink-${index}`, functionAddress: index, confidence: 1, evidence: [], limitations: [] })) },
    };
    backend.listCanonicalRuns.mockResolvedValue([run("binary")]);
    backend.loadCanonicalProjection.mockResolvedValue(result);
    render(<BinaryScanPage />);
    await screen.findByText("crowded");
    const cves = screen.queryByRole("list", { name: "CVEs for crowded 1.0" }) ?? screen.getByText("CVE-test-0").closest("li")!.parentElement!;
    const semantic = screen.queryByRole("list", { name: "Semantic findings" }) ?? screen.getByText("sink-0").closest("li")!.parentElement!;
    expect(cves.children).toHaveLength(20);
    expect(semantic.children).toHaveLength(50);
    expect(cves).toHaveAttribute("aria-label", "CVEs for crowded 1.0");
    expect(semantic).toHaveAttribute("aria-label", "Semantic findings");
    fireEvent.click(screen.getByRole("button", { name: "Last page of CVEs for crowded 1.0" }));
    fireEvent.click(screen.getByRole("button", { name: "Last page of semantic findings" }));
    expect(screen.getByText("CVE-test-9999")).toBeInTheDocument();
    expect(await screen.findByText("sink-9999")).toBeInTheDocument();
    await waitFor(() => expect(cves.children).toHaveLength(20));
  });
});

it('an explicitly loaded upgrade group opens its exact off-page advisory detail', async () => {
  const vulnerabilities = Array.from({ length: 60 }, (_, index) => vulnerability(index));
  const result: DependencyScanResult = { summary: { path: target, lockfilesFound: [`${target}/package-lock.json`], packagesFound: 60, packagesQueried: 60, vulnerabilitiesFound: 60, durationMs: 1, advisoryCoverage: 'complete' }, dependencies: [], vulnerabilities };
  backend.listCanonicalRuns.mockResolvedValue([run('dependencies')]);
  backend.loadCanonicalProjection.mockResolvedValue(result);
  render(<DepsScanPage />);
  await screen.findByRole('row', { name: 'Select package-0 advisory GHSA-0' });
  expect(backend.loadCanonicalProjection).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Load complete upgrade decisions' }));
  await screen.findByText('Upgrade groups by installation and update entry point');
  fireEvent.click(screen.getByRole('button', { name: 'Last page of upgrade groups' }));
  fireEvent.click(screen.getByRole('button', { name: /package-59@1.0.0/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Review GHSA-59' }));
  const advisories = screen.getByRole('region', { name: 'Dependency vulnerabilities' });
  expect(within(advisories).getByText('Advisory 59')).toBeInTheDocument();
  expect(within(advisories).queryByText('Advisory 0')).not.toBeInTheDocument();
  expect(backend.loadCanonicalProjection).toHaveBeenCalledOnce();
});

it('a complete-decision failure cannot leave its error on the next restored receipt', async () => {
  const result: DependencyScanResult = { summary: { path: target, lockfilesFound: [], packagesFound: 1, packagesQueried: 1, vulnerabilitiesFound: 1, durationMs: 1, advisoryCoverage: 'complete' }, dependencies: [], vulnerabilities: [vulnerability(0)] };
  backend.listCanonicalRuns.mockResolvedValue([run('dependencies')]);
  backend.loadCanonicalProjection.mockResolvedValue(result);
  render(<DepsScanPage />);
  await screen.findByRole('row', { name: 'Select package-0 advisory GHSA-0' });
  backend.loadCanonicalProjection.mockRejectedValueOnce(new Error('A decision failed'));
  fireEvent.click(screen.getByRole('button', { name: 'Load complete upgrade decisions' }));
  await screen.findByText(/A decision failed/);
  const other = '/tmp/other-paging-fixture';
  backend.listCanonicalRuns.mockResolvedValue([{ ...run('dependencies'), id: 'other-receipt', targetLabel: other }]);
  fireEvent.change(screen.getByLabelText('Project folder path'), { target: { value: other } });
  const load = await screen.findByRole('button', { name: 'Load complete upgrade decisions' });
  expect(screen.queryByText(/A decision failed/)).not.toBeInTheDocument();
  expect(load).toBeEnabled();
});

it('a pending complete-decision action cannot disable another receipt or settle its newer action', async () => {
  const result: DependencyScanResult = { summary: { path: target, lockfilesFound: [], packagesFound: 1, packagesQueried: 1, vulnerabilitiesFound: 1, durationMs: 1, advisoryCoverage: 'complete' }, dependencies: [], vulnerabilities: [vulnerability(0)] };
  backend.listCanonicalRuns.mockResolvedValue([run('dependencies')]);
  backend.loadCanonicalProjection.mockResolvedValue(result);
  render(<DepsScanPage />);
  await screen.findByRole('row', { name: 'Select package-0 advisory GHSA-0' });
  let oldResolve!: (value: DependencyScanResult) => void, newResolve!: (value: DependencyScanResult) => void;
  backend.loadCanonicalProjection.mockImplementationOnce(() => new Promise<DependencyScanResult>(done => { oldResolve = done; }));
  fireEvent.click(screen.getByRole('button', { name: 'Load complete upgrade decisions' }));
  const other = '/tmp/other-paging-fixture';
  const next = { ...result, summary: { ...result.summary, path: other } };
  backend.listCanonicalRuns.mockResolvedValue([{ ...run('dependencies'), id: 'other-receipt', targetLabel: other }]);
  backend.loadCanonicalProjection.mockResolvedValue(next);
  fireEvent.change(screen.getByLabelText('Project folder path'), { target: { value: other } });
  const load = await screen.findByRole('button', { name: 'Load complete upgrade decisions' });
  expect(load).toBeEnabled();
  backend.loadCanonicalProjection.mockImplementationOnce(() => new Promise<DependencyScanResult>(done => { newResolve = done; }));
  fireEvent.click(load);
  await act(async () => oldResolve(result));
  expect(screen.getByRole('button', { name: 'Loading complete upgrade decisions…' })).toBeDisabled();
  expect(screen.queryByRole('region', { name: 'Dependency upgrade decisions' })).not.toBeInTheDocument();
  await act(async () => newResolve(next));
  expect(screen.getByRole('region', { name: 'Dependency upgrade decisions' })).toBeInTheDocument();
});
