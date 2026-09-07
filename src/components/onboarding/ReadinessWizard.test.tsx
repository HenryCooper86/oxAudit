import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { open } from "@tauri-apps/plugin-dialog";
import { api } from "../../lib/api";
import { useAppStore } from "../../lib/stores";
import { requestReadinessWizard } from "../../lib/readinessWizard";
import { useScanWorkStore } from "../../features/project-home/coordinator";
import { Dashboard } from "../../pages/Dashboard";
import { projectSettings, projectContext, sourceResult } from "../../../tests/fixtures/projectHome";
import type { ProjectContext } from "../../lib/types";
import { ReadinessWizard } from "./ReadinessWizard";
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
beforeEach(() => {
  localStorage.clear();
  useAppStore.setState({ settings: projectSettings, settingsLoadError: false,
    selectedProject: null, activeProject: null, page: "settings",
    aiReadiness: { status: "unconfigured", version: 0 } });
  useScanWorkStore.setState({ active: null, check: null });
  const unavailable = { available: false, program: null, version: null, source: null, message: null };
  vi.spyOn(api, "binaryToolStatus").mockResolvedValue({
    canScan: true, runtime: "native",
    native: { ...unavailable, available: true, program: "native" },
    cveBinTool: unavailable, grype: unavailable, docker: unavailable,
  });
  vi.spyOn(api, "listDataSources").mockResolvedValue([]);
  vi.spyOn(api, "inspectSourceProject").mockImplementation(async (path) => projectContext(path));
  vi.spyOn(api, "scanProject").mockImplementation(async (options) => sourceResult(options.path));
  vi.spyOn(api, "findLockfiles").mockResolvedValue([]);
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([]);
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([]);
  vi.spyOn(api, "listSourceRuns").mockResolvedValue([]);
  vi.spyOn(api, "setActiveProject").mockResolvedValue();
});
function nextToProject() {
  fireEvent.click(screen.getByRole("button", { name: "Continue" }));
  fireEvent.click(screen.getByRole("button", { name: "Continue" }));
  fireEvent.click(screen.getByRole("button", { name: "Continue without AI" }));
}
function enter(path: string) {
  fireEvent.change(screen.getByLabelText("First project folder"), { target: { value: path } });
}
test("first project requires an explicit check and hands canonical results to actual Home without AI", async () => {
  render(<ReadinessWizard />);
  nextToProject();
  expect(screen.getByRole("button", { name: "Check project" })).toBeDisabled();
  enter(" /alias ");
  expect(useScanWorkStore.getState().check).toBeNull();
  vi.mocked(api.inspectSourceProject).mockResolvedValue(projectContext("/canonical"));
  fireEvent.click(screen.getByRole("button", { name: "Check project" }));
  await waitFor(() => expect(useScanWorkStore.getState().check?.status).toBe("completed"));
  expect(useAppStore.getState().selectedProject).toBe("/canonical");
  expect(useAppStore.getState().page).toBe("dashboard");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  render(<Dashboard />);
  expect(await screen.findByText("Project check completed")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "View source findings" }));
  expect(useAppStore.getState().projectHandoff?.path).toBe("/canonical");
  expect(useAppStore.getState().projectHandoff?.runId).toBe("s");
});
test("missing folder reports actionable error and allows retry", async () => {
  vi.mocked(api.inspectSourceProject).mockRejectedValueOnce({ message: "Folder moved", code: "invalidTarget", retryable: true });
  render(<ReadinessWizard />); nextToProject(); enter("/missing");
  fireEvent.click(screen.getByRole("button", { name: "Check project" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Folder moved");
  expect(useAppStore.getState().selectedProject).toBeNull();
  expect(useScanWorkStore.getState().check).toBeNull();
  enter("/available"); fireEvent.click(screen.getByRole("button", { name: "Check project" }));
  await waitFor(() => expect(useScanWorkStore.getState().check?.status).toBe("completed"));
});
test("skip persists completion, reopening resumes a draft without automatically scanning", async () => {
  const view = render(<ReadinessWizard />); nextToProject(); enter("/draft");
  fireEvent.click(screen.getByRole("button", { name: "Skip for now" }));
  view.unmount(); render(<ReadinessWizard />);
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  act(() => requestReadinessWizard()); nextToProject(); enter("/draft");
  fireEvent.keyDown(document, { key: "Escape" });
  act(() => requestReadinessWizard()); nextToProject();
  expect(screen.getByLabelText("First project folder")).toHaveValue("/draft");
  expect(useScanWorkStore.getState().check).toBeNull();
});
test.each(["Escape", "Skip for now"])("%s invalidates inspection even after reopening", async (close) => {
  let resolve!: (value: ProjectContext) => void;
  vi.mocked(api.inspectSourceProject).mockImplementationOnce(() => new Promise((r) => { resolve = r; }));
  render(<ReadinessWizard />); nextToProject(); enter("/old");
  fireEvent.click(screen.getByRole("button", { name: "Check project" }));
  if (close === "Escape") fireEvent.keyDown(document, { key: "Escape" });
  else fireEvent.click(screen.getByRole("button", { name: close }));
  act(() => requestReadinessWizard()); nextToProject(); enter("/new");
  await act(async () => resolve(projectContext("/old")));
  expect(screen.getByLabelText("First project folder")).toHaveValue("/new");
  expect(useAppStore.getState().selectedProject).toBeNull();
  expect(useScanWorkStore.getState().check).toBeNull();
});
test("newer folder wins over a pending folder picker and picker errors are retryable", async () => {
  let resolve!: (value: string) => void;
  vi.mocked(open).mockImplementationOnce(() => new Promise((r) => { resolve = r; }));
  render(<ReadinessWizard />); nextToProject();
  fireEvent.click(screen.getByRole("button", { name: "Browse…" }));
  enter("/new"); await act(async () => resolve("/old"));
  expect(screen.getByLabelText("First project folder")).toHaveValue("/new");
  vi.mocked(open).mockRejectedValueOnce(new Error("Picker unavailable"));
  fireEvent.click(screen.getByRole("button", { name: "Browse…" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Picker unavailable");
});
test("late native picker result after skip and reopen cannot replace the current draft", async () => {
  let resolve!: (value: string) => void;
  vi.mocked(open).mockImplementationOnce(() => new Promise((r) => { resolve = r; }));
  render(<ReadinessWizard />); nextToProject();
  fireEvent.click(screen.getByRole("button", { name: "Browse…" }));
  fireEvent.click(screen.getByRole("button", { name: "Skip for now" }));
  act(() => requestReadinessWizard()); nextToProject(); enter("/new");
  await act(async () => resolve("/old"));
  expect(screen.getByLabelText("First project folder")).toHaveValue("/new");
});
test("new draft invalidates pending check and no check starts without loaded scan settings", async () => {
  let resolve!: (value: ProjectContext) => void;
  vi.mocked(api.inspectSourceProject).mockImplementationOnce(() => new Promise((r) => { resolve = r; }));
  render(<ReadinessWizard />); nextToProject(); enter("/old");
  fireEvent.click(screen.getByRole("button", { name: "Check project" }));
  enter("/new"); await act(async () => resolve(projectContext("/old")));
  expect(useScanWorkStore.getState().check).toBeNull();
  act(() => useAppStore.setState({ settings: null, settingsLoadError: true }));
  expect(screen.getByRole("button", { name: "Check project" })).toBeDisabled();
  expect(screen.getByText(/Settings could not be loaded/)).toBeInTheDocument();
});
test("readiness response from an earlier wizard session cannot overwrite a reopened session", async () => {
  let reject!: (error: Error) => void;
  vi.mocked(api.listDataSources).mockImplementationOnce(() => new Promise((_, r) => { reject = r; }));
  render(<ReadinessWizard />);
  fireEvent.click(screen.getByRole("button", { name: "Skip for now" }));
  act(() => requestReadinessWizard());
  fireEvent.click(screen.getByRole("button", { name: "Continue" }));
  await screen.findByText("0 sources registered; 0 currently available offline.");
  await act(async () => reject(new Error("old session failure")));
  expect(screen.getByText("0 sources registered; 0 currently available offline.")).toBeInTheDocument();
  expect(screen.queryByText(/Some readiness details were unavailable/)).not.toBeInTheDocument();
});
