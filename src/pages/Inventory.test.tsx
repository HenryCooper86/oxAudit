import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { api } from "../lib/api";
import type { CanonicalRun, InventoryView } from "../lib/types";
import { InventoryPage } from "./Inventory";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

function run(id: string, kind: CanonicalRun["kind"], state: CanonicalRun["state"] = "completed"): CanonicalRun {
  return { id, kind, state, targetLabel: id, attempt: 1, createdAtMs: 1, updatedAtMs: 2,
    engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] };
}
function inventory(id: string, kind: CanonicalRun["kind"] = "binary"): InventoryView {
  return { runId: id, runKind: kind, targetLabel: id, updatedAtMs: 2, providerSnapshotCount: 0,
    components: [{ id: `component-${id}`, name: `Package ${id}`, version: "1", supplier: null,
      ecosystem: "generic", purl: null, cpes: [], aliases: [], identities: [], advisoryIds: [] }] };
}

test("completed image evidence is selectable and its components remain inspectable", async () => {
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([run("image-incomplete", "image", "incomplete"), run("image-saved", "image")]);
  vi.spyOn(api, "loadInventory").mockResolvedValue(inventory("image-saved", "image"));
  render(<InventoryPage />);
  expect(await screen.findByRole("heading", { name: "Package image-saved 1" })).toBeInTheDocument();
  expect(screen.getByLabelText("Completed inventory run")).toHaveValue("image-saved");
  expect(screen.queryByRole("option", { name: /image-incomplete/ })).not.toBeInTheDocument();
  expect(api.loadInventory).toHaveBeenCalledWith("image-saved");
});

test("changing runs hides the previous inventory's identity and counts while loading", async () => {
  let finish!: (value: InventoryView) => void;
  const pending = new Promise<InventoryView>(resolve => { finish = resolve; });
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([run("A", "binary"), run("B", "dependencies")]);
  vi.spyOn(api, "loadInventory").mockImplementation(id => id === "A" ? Promise.resolve(inventory("A")) : pending);
  render(<InventoryPage />);
  await screen.findByRole("heading", { name: "Package A 1" });
  await userEvent.selectOptions(screen.getByLabelText("Completed inventory run"), "B");
  expect(screen.queryByText("binary · A")).not.toBeInTheDocument();
  expect(screen.queryByText("1 components")).not.toBeInTheDocument();
  expect(screen.getByText("Loading component evidence")).toBeInTheDocument();
  await act(async () => finish(inventory("B", "dependencies")));
  await waitFor(() => expect(screen.getByRole("heading", { name: "Package B 1" })).toBeInTheDocument());
});
