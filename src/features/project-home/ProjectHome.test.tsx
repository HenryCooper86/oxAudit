import {
  projectSettings,
  projectContext as context,
  sourceResult,
} from "../../../tests/fixtures/projectHome";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../../lib/api";
import { useAppStore } from "../../lib/stores";
import { useScanWorkStore } from "./coordinator";
import { Dashboard } from "../../pages/Dashboard";
import { StatusBar } from "../../components/workbench/StatusBar";
import type { ProjectContext, ScanRunDetail } from "../../lib/types";
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
beforeEach(() => {
  useAppStore.setState({
    selectedProject: null,
    activeProject: null,
    projectHandoff: null,
    page: "dashboard",
    settings: projectSettings,
  });
  useScanWorkStore.setState({ active: null, check: null });
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([]);
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([]);
  vi.spyOn(api, "listSourceRuns").mockResolvedValue([]);
  vi.spyOn(api, "inspectSourceProject").mockImplementation(async (path) =>
    context(path),
  );
  vi.spyOn(api, "setActiveProject").mockResolvedValue();
});
test("home exposes loading, durable empty state and retryable load failures", async () => {
  let resolve!: (value: never[]) => void;
  vi.mocked(api.listSourceProjects).mockImplementationOnce(
    () =>
      new Promise((r) => {
        resolve = r;
      }),
  );
  render(<Dashboard />);
  expect(screen.getByText("Loading project history…")).toBeInTheDocument();
  await act(async () => resolve([]));
  expect(screen.getByText(/No saved projects/)).toBeInTheDocument();
  vi.mocked(api.listSourceProjects).mockRejectedValueOnce(
    new Error("database locked"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Refresh projects" }));
  expect(await screen.findByText(/database locked/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Refresh projects" }));
  await waitFor(() =>
    expect(screen.queryByText(/database locked/)).not.toBeInTheDocument(),
  );
});
test("restored selection is inspected without scanning and resume hands off canonical target", async () => {
  useAppStore.setState({ selectedProject: "/alias" });
  vi.mocked(api.inspectSourceProject).mockResolvedValue(context("/canonical"));
  const scan = vi.spyOn(api, "scanProject");
  render(<Dashboard />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Resume project" }),
  );
  expect(useAppStore.getState().projectHandoff?.path).toBe("/canonical");
  expect(useAppStore.getState().page).toBe("source-scan");
  expect(scan).not.toHaveBeenCalled();
});
test("unavailable restored path stays visible, and stale inspection cannot replace a newer selection", async () => {
  useAppStore.setState({ selectedProject: "/missing" });
  vi.mocked(api.inspectSourceProject).mockRejectedValueOnce(
    new Error("folder missing"),
  );
  render(<Dashboard />);
  expect(await screen.findByText(/folder missing/)).toBeInTheDocument();
  expect(screen.getByLabelText("Project folder")).toHaveValue("/missing");
  let resolve!: (value: ProjectContext) => void;
  vi.mocked(api.inspectSourceProject).mockImplementationOnce(
    () =>
      new Promise((r) => {
        resolve = r;
      }),
  );
  fireEvent.change(screen.getByLabelText("Project folder"), {
    target: { value: "/old" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Open project" }));
  fireEvent.change(screen.getByLabelText("Project folder"), {
    target: { value: "/new" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Open project" }));
  await screen.findByRole("button", { name: "Resume project" });
  await act(async () => resolve(context("/old")));
  expect(useAppStore.getState().selectedProject).toBe("/new");
  expect(screen.getByLabelText("Project folder")).toHaveValue("/new");
});
test("explicit project check survives leaving home and global cancellation blocks dependency work", async () => {
  useAppStore.setState({ selectedProject: "/project" });
  let finish!: (value: ScanRunDetail) => void;
  vi.spyOn(api, "scanProject").mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  vi.spyOn(api, "cancelScan").mockResolvedValue();
  const deps = vi.spyOn(api, "scanDependencies");
  const view = render(
    <>
      <Dashboard />
      <StatusBar />
    </>,
  );
  fireEvent.click(await screen.findByRole("button", { name: "Check project" }));
  await waitFor(() =>
    expect(useScanWorkStore.getState().active?.stage).toBe("Scanning source"),
  );
  view.rerender(<StatusBar />);
  expect(screen.getByRole("status")).toHaveTextContent("/project");
  fireEvent.click(screen.getByRole("button", { name: "Cancel active scan" }));
  await act(async () => finish(sourceResult("/project")));
  expect(useScanWorkStore.getState().check?.status).toBe("cancelled");
  expect(deps).not.toHaveBeenCalled();
});
test("completed check and source failure remain visible with result navigation", async () => {
  useAppStore.setState({ selectedProject: "/project" });
  vi.spyOn(api, "scanProject").mockResolvedValue(sourceResult("/project"));
  vi.spyOn(api, "findLockfiles").mockResolvedValue([]);
  render(<Dashboard />);
  fireEvent.click(await screen.findByRole("button", { name: "Check project" }));
  expect(
    await screen.findByText("Project check completed"),
  ).toBeInTheDocument();
  expect(screen.getByText(/Dependencies: not applicable/)).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "View source findings" }),
  ).toBeInTheDocument();
  vi.mocked(api.scanProject).mockRejectedValue(new Error("source failed"));
  fireEvent.click(screen.getByRole("button", { name: "Check project" }));
  expect(await screen.findByText("Project check failed")).toBeInTheDocument();
  expect(screen.getByText(/source failed/)).toBeInTheDocument();
});

test("recent dependency-only rows are buttons that resume dependencies while source counts remain unknown", async () => {
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([
    {
      id: "dep",
      kind: "dependencies",
      targetLabel: "/deps",
      state: "failed",
      attempt: 1,
      createdAtMs: 100,
      updatedAtMs: 200,
      engineIds: [],
      rulePackIds: [],
      providerSnapshotIds: [],
      warnings: [],
    },
  ]);
  render(<Dashboard />);
  fireEvent.click(
    await screen.findByRole("button", {
      name: /deps.*Source not checked.*Dependencies failed/,
    }),
  );
  const resume = await screen.findByRole("button", { name: "Resume project" });
  expect(screen.getByText("Source counts: unknown")).toBeInTheDocument();
  expect(screen.getByText("Dependencies: failed")).toBeInTheDocument();
  fireEvent.click(resume);
  expect(useAppStore.getState().projectHandoff?.path).toBe("/deps");
  expect(useAppStore.getState().page).toBe("deps-scan");
});

test("saved source counts stay labelled as previous evidence after an incomplete attempt", async () => {
  useAppStore.setState({ selectedProject: "/project" });
  vi.mocked(api.listSourceProjects).mockResolvedValue([
    {
      projectId: "/project",
      canonicalPath: "/project",
      displayName: "project",
      lastOpenedAt: "2026-09-07T00:00:00Z",
      lastCompletedRunId: "old",
      lastCompletedAt: "2026-09-06T00:00:00Z",
      openFindings: 0,
      critical: 0,
      high: 0,
    },
  ]);
  vi.mocked(api.listSourceRuns).mockResolvedValue([
    {
      runId: "failed",
      projectId: "/project",
      status: "incomplete",
      startedAt: "2026-09-07T00:00:00Z",
      completedAt: null,
      totalFindings: 0,
      newFindings: 0,
      resolvedFindings: 0,
    severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    },
  ]);
  render(<Dashboard />);
  expect(await screen.findByText("Source: incomplete")).toBeInTheDocument();
  expect(
    screen.getByText("0 source open · 0 critical · 0 high"),
  ).toBeInTheDocument();
  expect(
    screen.getByText(/Counts reflect the last completed/),
  ).toBeInTheDocument();
  expect(screen.queryByText(/safe|clean/i)).not.toBeInTheDocument();
});

test("native structured selection errors expose their actionable message", async () => {
  useAppStore.setState({ selectedProject: "/missing" });
  vi.mocked(api.inspectSourceProject).mockRejectedValue({
    code: "invalidTarget",
    message: "Project folder moved",
    retryable: true,
  });
  render(<Dashboard />);
  expect(await screen.findByText(/Project folder moved/)).toBeInTheDocument();
});

test("inspecting a dependency-only project does not redirect Resume to empty source results", async () => {
  useAppStore.setState({ selectedProject: "/deps" });
  vi.mocked(api.listSourceProjects).mockResolvedValue([
    {
      projectId: "/deps",
      canonicalPath: "/deps",
      displayName: "deps",
      lastOpenedAt: "2026-09-07",
      lastCompletedRunId: null,
      lastCompletedAt: null,
      openFindings: 0,
      critical: 0,
      high: 0,
    },
  ]);
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([
    {
      id: "dep",
      kind: "dependencies",
      targetLabel: "/deps",
      state: "completed",
      attempt: 1,
      createdAtMs: 100,
      updatedAtMs: 200,
      engineIds: [],
      rulePackIds: [],
      providerSnapshotIds: [],
      warnings: [],
    },
  ]);
  render(<Dashboard />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Resume project" }),
  );
  expect(useAppStore.getState().page).toBe("deps-scan");
});

test("a delayed A check finishes on A without replacing newer native and visible selection B", async () => {
  useAppStore.setState({ selectedProject: "/a" });
  let nativePath: string | null = null;
  vi.mocked(api.setActiveProject).mockImplementation(async (path) => {
    nativePath = path;
  });
  vi.spyOn(api, "scanProject").mockImplementation(async (options) =>
    sourceResult(options.path),
  );
  vi.spyOn(api, "findLockfiles").mockResolvedValue([]);
  render(<Dashboard />);
  const check = await screen.findByRole("button", { name: "Check project" });
  let finishInspection!: (project: ProjectContext) => void;
  vi.mocked(api.inspectSourceProject).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finishInspection = resolve;
      }),
  );
  fireEvent.click(check);
  fireEvent.change(screen.getByLabelText("Project folder"), {
    target: { value: "/b" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Open project" }));
  await waitFor(() => expect(nativePath).toBe("/b"));
  await act(async () => finishInspection(context("/a")));
  await waitFor(() =>
    expect(useScanWorkStore.getState().check?.status).toBe("completed"),
  );
  expect(api.scanProject).toHaveBeenCalledWith(
    expect.objectContaining({ path: "/a" }),
    expect.any(String),
  );
  expect(nativePath).toBe("/b");
  expect(useAppStore.getState().activeProject).toBe("/b");
  expect(useAppStore.getState().selectedProject).toBe("/b");
  expect(screen.getByLabelText("Project folder")).toHaveValue("/b");
});

test("home hides stale review counts when current policy cannot be projected", async () => {
  useAppStore.setState({ selectedProject: "/project" });
  vi.mocked(api.listSourceProjects).mockResolvedValue([{
    projectId: "/project", canonicalPath: "/project", displayName: "project",
    lastOpenedAt: "2026-09-07T00:00:00Z", lastCompletedRunId: "old",
    lastCompletedAt: "2026-09-06T00:00:00Z", openFindings: 0, critical: 0, high: 0,
    ...{ countsAvailable: false },
  }]);
  render(<Dashboard />);
  expect(await screen.findByText("Source counts: unavailable — refresh when the project is accessible.")).toBeInTheDocument();
  expect(screen.queryByText("0 source open · 0 critical · 0 high")).not.toBeInTheDocument();
  expect(screen.getAllByText(/Last checked:/).length).toBeGreaterThan(0);
});
