import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../lib/api";
import type { CanonicalRun, InventoryPage, ResultPage } from "../lib/types";
import { InventoryPage as InventoryScreen } from "./Inventory";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
function run(id: string, kind: CanonicalRun["kind"]): CanonicalRun {
  return { id, kind, state:"completed", targetLabel: id, attempt: 1, createdAtMs: 1, updatedAtMs: 2,
    engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] };
}
function runs(items: CanonicalRun[], total = items.length, offset = 0): ResultPage<CanonicalRun> {
  return { items, total, filteredTotal:total, offset, limit:50 };
}
function inventory(id: string, kind: CanonicalRun["kind"] = "binary", total = 1, filteredTotal = total, offset = 0): InventoryPage {
  return { runId: id, runKind: kind, targetLabel: id, updatedAtMs: 2, providerSnapshotCount: 0,
    total, filteredTotal, offset, limit:50,
    items: [{ id: `component-${id}`, name: `Package ${id}`, version: "1", supplier: null,
      ecosystem: "generic", purl: null, cpes: [], aliases: [], identities: [], advisoryIds: [] }] };
}
beforeEach(() => {
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([]);
  vi.spyOn(api, "loadInventory").mockRejectedValue("Full inventory should not load");
});

test("completed image evidence is selectable without downloading the complete inventory", async () => {
  vi.spyOn(api, "listInventoryRuns").mockResolvedValue(runs([run("image-saved", "image")]));
  vi.spyOn(api, "loadInventoryPage").mockResolvedValue(inventory("image-saved", "image"));
  render(<InventoryScreen />);
  expect(await screen.findByRole("heading", { name: "Package image-saved 1" })).toBeInTheDocument();
  expect(screen.getByLabelText("Completed inventory run")).toHaveValue("image-saved");
  expect(api.loadInventoryPage).toHaveBeenCalledWith("image-saved", expect.objectContaining({offset:0,limit:50}));
  expect(api.listCanonicalRuns).not.toHaveBeenCalled();
  expect(api.loadInventory).not.toHaveBeenCalled();
});

test("changing runs hides the previous inventory's identity and counts while loading", async () => {
  const pending = deferred<InventoryPage>();
  vi.spyOn(api, "listInventoryRuns").mockResolvedValue(runs([run("A", "binary"), run("B", "dependencies")]));
  vi.spyOn(api, "loadInventoryPage").mockImplementation(id => id === "A" ? Promise.resolve(inventory("A")) : pending.promise);
  render(<InventoryScreen />);
  await screen.findByRole("heading", { name: "Package A 1" });
  await userEvent.selectOptions(screen.getByLabelText("Completed inventory run"), "B");
  expect(screen.queryByText("binary · A")).not.toBeInTheDocument();
  expect(screen.queryByText("1 components")).not.toBeInTheDocument();
  expect(screen.getByText("Loading saved results")).toBeInTheDocument();
  await act(async () => pending.resolve(inventory("B", "dependencies")));
  expect(screen.getByRole("heading", { name: "Package B 1" })).toBeInTheDocument();
});

test("older inventory runs remain accessible beyond the first hundred", async () => {
  vi.spyOn(api, "listInventoryRuns").mockImplementation(async query => query?.offset === 100
    ? runs([run("old-image", "image")], 120, 100) : runs([run("recent", "binary")], 120));
  vi.spyOn(api, "loadInventoryPage").mockImplementation(async id => inventory(id));
  render(<InventoryScreen />);
  await screen.findByRole("heading", { name: "Package recent 1" });
  await userEvent.click(screen.getByRole("button", { name: "Last page of inventory runs" }));
  expect(await screen.findByRole("option", { name: /old-image/ })).toBeInTheDocument();
  expect(await screen.findByRole("heading", { name: "Package old-image 1" })).toBeInTheDocument();
  expect(api.listInventoryRuns).toHaveBeenCalledWith(expect.objectContaining({offset:100,limit:50}));
});

test("deep component pages and search use authoritative totals and reject delayed old rows", async () => {
  const pending = deferred<InventoryPage>();
  vi.spyOn(api, "listInventoryRuns").mockResolvedValue(runs([run("A", "binary")]));
  vi.spyOn(api, "loadInventoryPage").mockImplementation(async (_id, query) => query?.search
    ? inventory("match", "binary", 205, 1) : query?.offset === 200 ? pending.promise : inventory("A", "binary", 205));
  render(<InventoryScreen />);
  await screen.findByRole("heading", { name: "Package A 1" });
  await userEvent.click(screen.getByRole("button", { name: "Last page of inventory components" }));
  expect(screen.queryByRole("heading", { name: "Package A 1" })).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Search inventory"), {target:{value:"cve-2026-1234"}});
  expect(await screen.findByRole("heading", { name: "Package match 1" })).toBeInTheDocument();
  expect(screen.getByText("1 of 205 components")).toBeInTheDocument();
  await act(async () => pending.resolve(inventory("stale", "binary", 205, 205, 200)));
  expect(screen.queryByRole("heading", { name: "Package stale 1" })).not.toBeInTheDocument();
  expect(api.loadInventoryPage).toHaveBeenLastCalledWith("A", {search:"cve-2026-1234",offset:0,limit:50});
});

test("a failed component page can be retried without losing the selected run", async () => {
  vi.spyOn(api, "listInventoryRuns").mockResolvedValue(runs([run("A", "binary")]));
  vi.spyOn(api, "loadInventoryPage").mockRejectedValueOnce("Temporary database failure").mockResolvedValue(inventory("A"));
  render(<InventoryScreen />);
  expect(await screen.findByText("Temporary database failure")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Retry page" }));
  expect(await screen.findByRole("heading", { name: "Package A 1" })).toBeInTheDocument();
  expect(screen.getByLabelText("Completed inventory run")).toHaveValue("A");
});

test.each(["runs", "components"] as const)("a failed deep %s page stays available for retry", async kind => {
  const runPages = vi.spyOn(api, "listInventoryRuns")
    .mockResolvedValue(runs([run("A", "binary")], kind === "runs" ? 120 : 1));
  const componentPages = vi.spyOn(api, "loadInventoryPage")
    .mockResolvedValue(inventory("A", "binary", 120));
  render(<InventoryScreen />);
  await screen.findByRole("heading", { name: "Package A 1" });
  if (kind === "runs") {
    runPages.mockRejectedValueOnce("Deep page unavailable").mockResolvedValue(runs([run("old", "image")], 120, 100));
  } else {
    componentPages.mockRejectedValueOnce("Deep page unavailable").mockResolvedValue(inventory("deep", "binary", 120, 120, 100));
  }
  await userEvent.click(screen.getByRole("button", { name: `Last page of inventory ${kind}` }));
  expect(await screen.findByText("Deep page unavailable")).toBeInTheDocument();
  const calls = kind === "runs" ? runPages.mock.calls.map(([q]) => q?.offset) : componentPages.mock.calls.map(([, q]) => q?.offset);
  expect(calls).toEqual([0, 100]);
  await userEvent.click(screen.getByRole("button", { name: "Retry page" }));
  if (kind === "runs") {
    expect(await screen.findByRole("option", { name: /old/ })).toBeInTheDocument();
    expect(runPages).toHaveBeenLastCalledWith(expect.objectContaining({offset:100}));
  } else {
    expect(await screen.findByRole("heading", { name: "Package deep 1" })).toBeInTheDocument();
    expect(componentPages).toHaveBeenLastCalledWith("A", expect.objectContaining({offset:100}));
  }
});
