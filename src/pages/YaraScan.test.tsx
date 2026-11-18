import { canonicalMetadata, canonicalPage } from "../../tests/fixtures/pagedResults";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../lib/api";
import { useAppStore } from "../lib/stores";
import { useScanWorkStore } from "../features/project-home/coordinator";
import { YaraScanPage } from "./YaraScan";
import type { InstalledSignaturePack, YaraMatchRow, YaraScanResult } from "../lib/types";

const handlers = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("../lib/events", () => ({ listen: async (name: string, callback: (event: { payload: unknown }) => void) => { handlers.set(name, callback); return () => handlers.delete(name); } }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const pack = (overrides: Partial<InstalledSignaturePack> = {}): InstalledSignaturePack => ({
  id: "yara.acme", kind: "yara", name: "Acme rules", version: "1", license: "MIT", source: "", authors: "", contentSha256: "a".repeat(64),
  fileCount: 1, ruleCount: 4, skipped: [], enabled: true, installedAt: "2026-11-18T00:00:00Z", protocols: null, notEvaluatedCount: 0, ...overrides,
});
const match = (overrides: Partial<YaraMatchRow> = {}): YaraMatchRow => ({
  id: "m1", path: "dir/sample.bin", filePath: "dir/sample.bin", sha256: "f".repeat(64), rule: "Marker_Rule", namespace: "rules/a.yar", pack: "yara.acme",
  ruleId: "yara.acme/rules/a.yar:Marker_Rule", tags: ["demo", "marker"], severity: "high", meta: [["author", "Ada"], ["score", 70], ["reviewed", true]],
  strings: [{ identifier: "$a", offset: 8000, length: 4, excerptHex: "4d41524b" }], stringsTruncated: 0, ...overrides,
});
const result = (overrides: Partial<YaraScanResult> = {}): YaraScanResult => ({
  runId: "run-1", target: "/scan", state: "completed", filesScanned: 12, bytesScanned: 4096, matches: [match()], matchesDropped: 0, skipped: [], skippedDropped: 0,
  packs: [{ id: "yara.acme", name: "Acme rules", license: "MIT", contentSha256: "a".repeat(64), ruleCount: 4 }], rulesCompiled: 4, rulesSkipped: [], rulesSkippedTotal: 0, notes: [], durationMs: 5, ...overrides,
});

beforeEach(() => {
  vi.restoreAllMocks();
  handlers.clear();
  useAppStore.setState({ page: "yara-scan", pageStatus: {}, activeProject: null, selectedProject: null, exportHandoff: null });
  useScanWorkStore.setState({ active: null, check: null, backend: { active: null, recent: [] }, lastTargets: {}, recoveryError: null });
  vi.spyOn(api, "listSignaturePacks").mockResolvedValue([pack()]);
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([]);
  vi.spyOn(api, "scanWorkStatus").mockResolvedValue({ active: null, recent: [] });
  vi.spyOn(api, "cancelScanWork").mockResolvedValue(true);
  vi.spyOn(api, "loadCanonicalProjectionMetadata").mockImplementation(async id => canonicalMetadata(await (api.loadCanonicalProjection as any).getMockImplementation?.()?.(id)));
});

async function typeTarget(path = "/scan") {
  fireEvent.change(await screen.findByLabelText("YARA target"), { target: { value: path } });
}
const runButton = () => screen.getByRole("button", { name: "Run YARA scan" });

test("without enabled YARA packs the page explains where to import rules and cannot run", async () => {
  vi.mocked(api.listSignaturePacks).mockResolvedValue([pack({ enabled: false }), pack({ id: "n", kind: "nuclei" })]);
  const scan = vi.spyOn(api, "scanYara");
  render(<YaraScanPage />);
  expect(await screen.findByText("No YARA rules are enabled")).toBeInTheDocument();
  await typeTarget();
  expect(runButton()).toBeDisabled();
  await userEvent.click(screen.getByRole("button", { name: "Open Rule Library" }));
  expect(useAppStore.getState().page).toBe("rule-library");
  expect(scan).not.toHaveBeenCalled();
});

test("a run sends the request, filters progress by operation, and renders the match detail with offsets and excerpt", async () => {
  vi.mocked(api.listSignaturePacks).mockResolvedValue([pack(), pack({ id: "yara.two", name: "Second rules" })]);
  let finish!: (value: YaraScanResult) => void;
  const scan = vi.spyOn(api, "scanYara").mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  render(<YaraScanPage />);
  await typeTarget();
  await screen.findByText(/Packs \(2 of 2 selected\)/);
  fireEvent.change(screen.getByLabelText("Max file size (MiB)"), { target: { value: "8" } });
  await userEvent.click(runButton());
  const operationId = useScanWorkStore.getState().active!.operationId;
  expect(scan).toHaveBeenCalledWith({ path: "/scan", maxFileSizeMb: 8, operationId });
  await act(async () => handlers.get("yara://progress")?.({ payload: { operationId: "other", message: "stale progress", done: 1, total: 2, bytesScanned: 1 } }));
  expect(screen.queryByText("stale progress")).not.toBeInTheDocument();
  await act(async () => handlers.get("yara://progress")?.({ payload: { operationId, message: "Scanned 3 of 12 files", done: 3, total: 12, bytesScanned: 2048 } }));
  expect(screen.getAllByText("Scanned 3 of 12 files").length).toBeGreaterThan(0);
  expect(screen.getByText("2,048 bytes read")).toBeInTheDocument();
  await act(async () => finish(result()));

  const list = await screen.findByRole("list", { name: "YARA matches" });
  expect(within(list).getByText("Marker_Rule")).toBeInTheDocument();
  expect(within(list).getByText("demo, marker")).toBeInTheDocument();
  expect(screen.getByText("1 rule match recorded")).toBeInTheDocument();
  await userEvent.click(within(list).getByRole("button", { name: /Marker_Rule/ }));
  const strings = await screen.findByRole("table", { name: "Matched strings" });
  expect(within(strings).getByText("0x1f40 (8,000)")).toBeInTheDocument();
  expect(within(strings).getByText("4d 41 52 4b")).toBeInTheDocument();
  expect(within(strings).getByLabelText("Printable rendering")).toHaveTextContent("MARK");
  expect(within(strings).getByText("4 bytes")).toBeInTheDocument();
  const meta = screen.getByRole("table", { name: "Rule metadata" });
  expect(within(meta).getByText("Ada")).toBeInTheDocument();
  expect(within(meta).getByText("true")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Open Export Center" }));
  expect(useAppStore.getState().exportHandoff).toEqual({ runId: "run-1" });
});

test("unticking a pack sends an explicit pack list and unticking all blocks the run", async () => {
  vi.mocked(api.listSignaturePacks).mockResolvedValue([pack(), pack({ id: "yara.two", name: "Second rules" })]);
  const scan = vi.spyOn(api, "scanYara").mockResolvedValue(result({ matches: [] }));
  render(<YaraScanPage />);
  await typeTarget();
  await userEvent.click(await screen.findByRole("checkbox", { name: /Second rules/ }));
  await userEvent.click(runButton());
  await waitFor(() => expect(scan).toHaveBeenCalled());
  expect(scan.mock.calls[0][0]).toMatchObject({ path: "/scan", packIds: ["yara.acme"] });
  await userEvent.click(screen.getByRole("checkbox", { name: /Acme rules/ }));
  expect(screen.getByText("Select at least one pack.")).toBeInTheDocument();
  expect(runButton()).toBeDisabled();
});

test("an invalid max file size blocks the run", async () => {
  render(<YaraScanPage />);
  await typeTarget();
  fireEvent.change(await screen.findByLabelText("Max file size (MiB)"), { target: { value: "0" } });
  expect(screen.getByText(/between 1 and 1,024/)).toBeInTheDocument();
  expect(runButton()).toBeDisabled();
  // Files are read into memory whole, so the cap stops at 1 GiB.
  fireEvent.change(screen.getByLabelText("Max file size (MiB)"), { target: { value: "1025" } });
  expect(screen.getByText(/between 1 and 1,024/)).toBeInTheDocument();
  expect(runButton()).toBeDisabled();
});

test("cancel goes through the coordinator and a late result is not shown", async () => {
  let finish!: (value: YaraScanResult) => void;
  vi.spyOn(api, "scanYara").mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  render(<YaraScanPage />);
  await typeTarget();
  await screen.findByText(/Packs/);
  await userEvent.click(runButton());
  const operationId = useScanWorkStore.getState().active!.operationId;
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  await waitFor(() => expect(api.cancelScanWork).toHaveBeenCalledWith(operationId));
  await act(async () => finish(result()));
  expect(await screen.findByText("YARA scan cancelled")).toBeInTheDocument();
  expect(screen.queryByRole("list", { name: "YARA matches" })).not.toBeInTheDocument();
  expect(useAppStore.getState().pageStatus["yara-scan"]?.label).toMatch(/cancelled/);
});

test("an incomplete run is a warning with its notes, never a completed one, and lists what was not applied or scanned", async () => {
  vi.spyOn(api, "scanYara").mockResolvedValue(result({
    state: "incomplete", matches: [], notes: ["big.bin timed out after 30 s"], skipped: [{ path: "big.bin", reason: "timed out" }], skippedDropped: 2,
    rulesSkipped: [{ pack: "yara.acme", file: "rules/bad.yar", line: 7, message: "undefined identifier" }], rulesSkippedTotal: 1,
  }));
  render(<YaraScanPage />);
  await typeTarget();
  await screen.findByText(/Packs/);
  await userEvent.click(runButton());
  expect(await screen.findByText("This run is incomplete")).toBeInTheDocument();
  expect(screen.getAllByText(/big\.bin timed out after 30 s/).length).toBeGreaterThan(0);
  expect(screen.getByText("No rule matched in the files that were scanned.")).toBeInTheDocument();
  const notApplied = screen.getByRole("region", { name: "Rule files that were not applied" });
  expect(within(notApplied).getByText("yara.acme/rules/bad.yar:7")).toBeInTheDocument();
  expect(within(notApplied).getByText("undefined identifier")).toBeInTheDocument();
  const notScanned = screen.getByRole("region", { name: "Not scanned" });
  expect(within(notScanned).getByText("big.bin")).toBeInTheDocument();
  expect(within(notScanned).getByText(/2 more were not listed/)).toBeInTheDocument();
  expect(useAppStore.getState().pageStatus["yara-scan"]?.label).toMatch(/incomplete/);
  expect(useAppStore.getState().pageStatus["yara-scan"]?.tone).not.toBe("success");
  expect(document.body.textContent ?? "").not.toMatch(/\b(clean|safe|secure)\b/i);
});

test("the search and severity filters narrow live matches", async () => {
  vi.spyOn(api, "scanYara").mockResolvedValue(result({ matches: [match(), match({ id: "m2", rule: "Other_Rule", severity: "low", path: "x.bin", filePath: "x.bin" })] }));
  render(<YaraScanPage />);
  await typeTarget();
  await screen.findByText(/Packs/);
  await userEvent.click(runButton());
  const list = await screen.findByRole("list", { name: "YARA matches" });
  expect(within(list).getAllByRole("listitem")).toHaveLength(2);
  fireEvent.change(screen.getByLabelText("Match severity"), { target: { value: "low" } });
  expect(within(screen.getByRole("list", { name: "YARA matches" })).getAllByRole("listitem")).toHaveLength(1);
  fireEvent.change(screen.getByLabelText("Match severity"), { target: { value: "all" } });
  fireEvent.change(screen.getByLabelText("Search matches"), { target: { value: "marker_rule" } });
  expect(within(screen.getByRole("list", { name: "YARA matches" })).getAllByRole("listitem")).toHaveLength(1);
});

test("the latest saved run for the typed target reopens with paged matches and a Not scanned section", async () => {
  const saved = result({ runId: "saved-yara", matches: Array.from({ length: 60 }, (_, index) => match({ id: `m${index}`, rule: `Rule_${String(index).padStart(2, "0")}`, path: `f${index}.bin`, filePath: `f${index}.bin` })), skipped: [{ path: "huge.iso", reason: "larger than 64 MiB" }] });
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([{ id: "saved-yara", kind: "yara", targetLabel: "/scan", state: "completed", attempt: 1, createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] }]);
  vi.spyOn(api, "loadCanonicalProjection").mockResolvedValue(saved as never);
  vi.mocked(api.loadCanonicalProjectionMetadata).mockImplementation(async () => canonicalMetadata(saved));
  const page = vi.spyOn(api, "loadCanonicalProjectionPage").mockImplementation((async (_id: string, section: never, query: never) => canonicalPage(saved, section, query)) as never);
  render(<YaraScanPage />);
  await typeTarget();
  const list = await screen.findByRole("list", { name: "YARA matches" });
  await waitFor(() => expect(within(list).getAllByRole("listitem")).toHaveLength(50));
  expect(page).toHaveBeenCalledWith("saved-yara", "matches", expect.objectContaining({ offset: 0, limit: 50 }));
  await userEvent.click(screen.getByRole("button", { name: "Next page of YARA matches" }));
  await waitFor(() => expect(within(screen.getByRole("list", { name: "YARA matches" })).getAllByRole("listitem")).toHaveLength(10));
  expect(await screen.findByText("huge.iso")).toBeInTheDocument();
  expect(page).toHaveBeenCalledWith("saved-yara", "skipped", expect.anything());
  fireEvent.change(screen.getByLabelText("Search matches"), { target: { value: "rule_07" } });
  await waitFor(() => expect(page).toHaveBeenCalledWith("saved-yara", "matches", expect.objectContaining({ search: "rule_07" })));
  await userEvent.click(screen.getByRole("button", { name: "Open Export Center" }));
  expect(useAppStore.getState().exportHandoff).toEqual({ runId: "saved-yara" });
});
