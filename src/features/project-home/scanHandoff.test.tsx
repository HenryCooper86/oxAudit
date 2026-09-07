import { projectSettings } from "../../../tests/fixtures/projectHome";
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
import { acquireScan, releaseScan, useScanWorkStore } from "./coordinator";
import { SourceScanPage } from "../../pages/SourceScan";
import { DepsScanPage } from "../../pages/DepsScan";
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => {}),
}));
vi.mock("@tauri-apps/api/webview", () => ({
  getCurrentWebview: () => ({ onDragDropEvent: async () => () => {} }),
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: vi.fn() }));
beforeEach(() => {
  useAppStore.setState({
    selectedProject: null,
    activeProject: null,
    projectHandoff: null,
    settingsLoadError: false,
    settings: projectSettings,
  });
  useScanWorkStore.setState({ active: null, check: null });
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([]);
  vi.spyOn(api, "listSourceRuns").mockResolvedValue([]);
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([]);
  vi.spyOn(api, "inspectSourceProject").mockImplementation(async (path) => ({
    projectId: path,
    canonicalPath: path,
    displayName: path,
    policy: { status: "missing" },
    lastCompletedRunId: null,
    lastOptions: null,
  }));
  vi.spyOn(api, "setActiveProject").mockResolvedValue();
});
test("source opens active project and accepts another palette target while mounted without scanning", async () => {
  useAppStore.setState({ activeProject: "/first" });
  const scan = vi.spyOn(api, "scanProject");
  render(<SourceScanPage />);
  expect(screen.getByLabelText("Project folder path")).toHaveValue("/first");
  await act(async () => useAppStore.getState().setActiveProject("/second"));
  await waitFor(() =>
    expect(screen.getByLabelText("Project folder path")).toHaveValue("/second"),
  );
  await screen.findByText("Project ready");
  expect(scan).not.toHaveBeenCalled();
});
test("source runtime reply cannot overwrite pending user text", async () => {
  let finish!: () => void;
  vi.mocked(api.setActiveProject).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  useAppStore.setState({ activeProject: "/first" });
  render(<SourceScanPage />);
  await waitFor(() => expect(finish).toBeDefined());
  fireEvent.change(screen.getByLabelText("Project folder path"), {
    target: { value: "/pending" },
  });
  await act(async () => finish());
  expect(screen.getByLabelText("Project folder path")).toHaveValue("/pending");
});
test("home handoff reaches already mounted dependency page and ownership disables manual scan", async () => {
  render(<DepsScanPage />);
  await act(async () =>
    useAppStore.getState().openProject("/target", "deps-scan"),
  );
  expect(screen.getByLabelText("Project folder path")).toHaveValue("/target");
  let id!: number;
  await act(async () => {
    id = acquireScan("project", "/other", "Scanning source")!;
  });
  expect(
    screen.getByRole("button", { name: "Check dependencies" }),
  ).toBeDisabled();
  await act(async () => releaseScan(id));
  expect(
    screen.getByRole("button", { name: "Check dependencies" }),
  ).toBeEnabled();
});

test("source page cancel during runtime preparation prevents the native scan from starting", async () => {
  useAppStore.setState({ activeProject: "/project" });
  render(<SourceScanPage />);
  await screen.findByText("Project ready");
  await waitFor(() => expect(api.setActiveProject).toHaveBeenCalled());
  let finish!: () => void;
  vi.mocked(api.setActiveProject).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const scan = vi.spyOn(api, "scanProject");
  vi.spyOn(api, "cancelScan").mockResolvedValue();
  fireEvent.click(screen.getByRole("button", { name: "Run scan" }));
  await waitFor(() => expect(finish).toBeDefined());
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  await act(async () => finish());
  expect(scan).not.toHaveBeenCalled();
});

test("dependency runtime reply preserves pending user path", async () => {
  let finish!: () => void;
  vi.mocked(api.setActiveProject).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  render(<DepsScanPage />);
  fireEvent.change(screen.getByLabelText("Project folder path"), {
    target: { value: "/first" },
  });
  fireEvent.change(screen.getByLabelText("Project folder path"), {
    target: { value: "/pending" },
  });
  await act(async () => finish());
  expect(screen.getByLabelText("Project folder path")).toHaveValue("/pending");
});

test("dependency result handoff displays the check receipt instead of a newer unrelated history projection", async () => {
  const { dependencyResult } =
    await import("../../../tests/fixtures/projectHome");
  const receipt = dependencyResult("/target");
  receipt.summary.packagesFound = 23;
  await act(async () =>
    useAppStore
      .getState()
      .openProject("/target", "deps-scan", undefined, receipt),
  );
  render(<DepsScanPage />);
  await waitFor(() =>
    expect(screen.getByLabelText("Dependency scan summary")).toHaveTextContent(
      "23",
    ),
  );
  expect(api.listCanonicalRuns).not.toHaveBeenCalled();
});

test("unsaved source check receipt opens with retry-save controls and no automatic scan", async () => {
  const { sourceResult } = await import("../../../tests/fixtures/projectHome");
  const receipt = sourceResult("/project");
  receipt.persistence = { status: "notSaved", retryToken: "retry-token" };
  useScanWorkStore.setState({
    check: {
      path: "/project",
      status: "incomplete",
      source: "completed, not saved",
      dependencies: "not applicable",
      sourceResult: receipt,
    },
  });
  useAppStore.getState().openProject("/project", "source-scan", "s");
  const scan = vi.spyOn(api, "scanProject");
  render(<SourceScanPage />);
  expect(
    await screen.findByRole("button", { name: /Retry save/ }),
  ).toBeInTheDocument();
  expect(scan).not.toHaveBeenCalled();
});

test("retry save repairs the shared source receipt through leaving and reopening results", async () => {
  const { sourceResult } = await import("../../../tests/fixtures/projectHome");
  const saved = sourceResult("/project");
  const unsaved = {
    ...saved,
    persistence: { status: "notSaved" as const, retryToken: "obsolete" },
  };
  useScanWorkStore.setState({
    check: {
      path: "/project",
      status: "incomplete",
      source: "completed, not saved",
      dependencies: "not applicable",
      sourceResult: unsaved,
    },
  });
  useAppStore.getState().openProject("/project", "source-scan", "s");
  vi.spyOn(api, "retrySourceRunSave").mockResolvedValue(saved);
  vi.spyOn(api, "loadSourceRun").mockResolvedValue(saved);
  const sourceView = render(<SourceScanPage />);
  fireEvent.click(await screen.findByRole("button", { name: /Retry save/ }));
  await waitFor(() =>
    expect(
      screen.queryByRole("button", { name: /Retry save/ }),
    ).not.toBeInTheDocument(),
  );
  sourceView.unmount();
  const { Dashboard } = await import("../../pages/Dashboard");
  const home = render(<Dashboard />);
  expect(
    await screen.findByText("Project check completed"),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "View source findings" }));
  home.unmount();
  render(<SourceScanPage />);
  await waitFor(() => expect(api.loadSourceRun).toHaveBeenCalledWith("s"));
  expect(
    screen.queryByRole("button", { name: /Retry save/ }),
  ).not.toBeInTheDocument();
  expect(useScanWorkStore.getState().check?.sourceResult?.persistence).toEqual({
    status: "saved",
  });
});

test("zero queryable dependency packages do not imply an OSV request", async () => {
  const { dependencyResult } =
    await import("../../../tests/fixtures/projectHome");
  const receipt = dependencyResult("/project");
  receipt.summary.packagesFound = 0;
  receipt.summary.packagesQueried = 0;
  useAppStore
    .getState()
    .openProject("/project", "deps-scan", undefined, receipt);
  render(<DepsScanPage />);
  expect(await screen.findByText("No packages to query")).toBeInTheDocument();
  expect(screen.getByText(/No OSV request/)).toBeInTheDocument();
  expect(screen.queryByText(/OSV returned/)).not.toBeInTheDocument();
});

test("a late save cannot replace a newer run handoff on the same project", async () => {
  const { sourceResult } = await import("../../../tests/fixtures/projectHome");
  const old = sourceResult("/project");
  const newer = {
    ...sourceResult("/project"),
    runId: "newer",
    summary: { ...old.summary, filesScanned: 99 },
  };
  useScanWorkStore.setState({
    check: {
      path: "/project",
      status: "incomplete",
      source: "completed, not saved",
      dependencies: "not applicable",
      sourceResult: {
        ...old,
        persistence: { status: "notSaved", retryToken: "retry" },
      },
    },
  });
  useAppStore.getState().openProject("/project", "source-scan", "s");
  let finish!: (value: typeof old) => void;
  vi.spyOn(api, "retrySourceRunSave").mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  vi.spyOn(api, "loadSourceRun").mockResolvedValue(newer);
  render(<SourceScanPage />);
  fireEvent.click(await screen.findByRole("button", { name: /Retry save/ }));
  await act(async () =>
    useAppStore.getState().openProject("/project", "source-scan", "newer"),
  );
  expect(await screen.findByText("99")).toBeInTheDocument();
  await act(async () => finish(old));
  expect(screen.getByText("99")).toBeInTheDocument();
  expect(
    useScanWorkStore.getState().check?.sourceResult?.persistence.status,
  ).toBe("saved");
});

const savedDependencyRun = {
  id: "saved-dependencies",
  kind: "dependencies" as const,
  targetLabel: "/project",
  state: "completed" as const,
  attempt: 1,
  createdAtMs: 100,
  updatedAtMs: 200,
  engineIds: [],
  rulePackIds: [],
  providerSnapshotIds: [],
  warnings: [],
};

test("initial same-path home handoff restores durable dependencies after restart without a check receipt", async () => {
  const { dependencyResult } =
    await import("../../../tests/fixtures/projectHome");
  const saved = dependencyResult("/project");
  saved.summary.packagesFound = 37;
  useAppStore.setState({
    activeProject: "/project",
    selectedProject: "/project",
  });
  useAppStore.getState().openProject("/project", "deps-scan");
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([
    {
      ...savedDependencyRun,
      id: "cancelled-dependencies",
      state: "cancelled",
      updatedAtMs: 300,
    },
    savedDependencyRun,
  ]);
  vi.spyOn(api, "loadCanonicalProjection").mockResolvedValue(saved);
  const scan = vi.spyOn(api, "scanDependencies");
  render(<DepsScanPage />);
  expect(await screen.findByText("37")).toBeInTheDocument();
  expect(screen.getByLabelText("Project folder path")).toHaveValue("/project");
  expect(api.loadCanonicalProjection).toHaveBeenCalledWith(
    "saved-dependencies",
  );
  expect(scan).not.toHaveBeenCalled();
});

test("an already-mounted same-path home handoff reloads newly available durable dependencies", async () => {
  const { dependencyResult } =
    await import("../../../tests/fixtures/projectHome");
  const saved = dependencyResult("/project");
  saved.summary.packagesFound = 43;
  useAppStore.setState({
    activeProject: "/project",
    selectedProject: "/project",
  });
  render(<DepsScanPage />);
  await waitFor(() => expect(api.listCanonicalRuns).toHaveBeenCalled());
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([savedDependencyRun]);
  vi.spyOn(api, "loadCanonicalProjection").mockResolvedValue(saved);
  await act(async () =>
    useAppStore.getState().openProject("/project", "deps-scan"),
  );
  expect(await screen.findByText("43")).toBeInTheDocument();
});

test("a history response superseded by a fresh dependency scan cannot replace its results", async () => {
  const { dependencyResult } =
    await import("../../../tests/fixtures/projectHome");
  const old = dependencyResult("/project");
  old.summary.packagesFound = 13;
  const fresh = dependencyResult("/project");
  fresh.summary.packagesFound = 59;
  useAppStore.setState({
    activeProject: "/project",
    selectedProject: "/project",
  });
  useAppStore.getState().openProject("/project", "deps-scan");
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([savedDependencyRun]);
  let finish!: (result: typeof old) => void;
  vi.spyOn(api, "loadCanonicalProjection").mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  vi.spyOn(api, "scanDependencies").mockResolvedValue(fresh);
  render(<DepsScanPage />);
  await waitFor(() => expect(finish).toBeDefined());
  fireEvent.click(screen.getByRole("button", { name: "Check dependencies" }));
  expect(await screen.findByText("59")).toBeInTheDocument();
  await act(async () => finish(old));
  expect(screen.getByText("59")).toBeInTheDocument();
  expect(screen.queryByText("13")).not.toBeInTheDocument();
});
