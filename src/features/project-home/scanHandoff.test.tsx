import { installPagingFixtures } from "../../../tests/fixtures/pagedResults";
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
import { listen } from "@tauri-apps/api/event";
import { useAppStore } from "../../lib/stores";
import { acquireScan, releaseScan, useScanWorkStore } from "./coordinator";
import { SourceScanPage } from "../../pages/SourceScan";
import { DepsScanPage } from "../../pages/DepsScan";
import { flushSync } from "react-dom";
import { StatusBar } from "../../components/workbench/StatusBar";
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
  installPagingFixtures(api);
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
  await waitFor(() => expect(api.loadSourceRunMetadata).toHaveBeenCalledWith("s"));
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
  expect(api.loadCanonicalProjectionMetadata).toHaveBeenCalledWith(
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


test.each(["success", "error"] as const)("fast dependency %s keeps terminal status through queued and late progress", async (terminal) => {
  const { dependencyResult } = await import("../../../tests/fixtures/projectHome");
  const receipt = dependencyResult("/project");
  receipt.summary.packagesFound = 0;
  receipt.summary.packagesQueried = 0;
  let progress!: (event: { payload: { phase: string; done: number; total: number } }) => void;
  vi.mocked(listen).mockImplementation(async (name, callback) => {
    if (name === "deps://progress") progress = callback as typeof progress;
    return () => {};
  });
  useAppStore.setState({ activeProject: "/project", page: "deps-scan", pageStatus: {} });
  vi.spyOn(api, "scanDependencies").mockImplementation(async () => {
    progress({ payload: { phase: "querying-osv", done: 0, total: 1 } });
    if (terminal === "error") throw new Error("incomplete advisory coverage");
    return receipt;
  });
  render(<><DepsScanPage /><StatusBar /></>);
  await waitFor(() => expect(progress).toBeDefined());
  // Flush one already queued native progress delivery when the terminal store
  // status publishes, before the async invocation's finally block can render.
  const stop = useAppStore.subscribe((state, previous) => {
    if (state.pageStatus["deps-scan"]?.tone === terminal && previous.pageStatus["deps-scan"]?.tone !== terminal) {
      flushSync(() => progress({ payload: { phase: "querying-osv", done: 0, total: 1 } }));
    }
  });
  fireEvent.click(screen.getByRole("button", { name: "Check dependencies" }));
  await waitFor(() => expect(api.scanDependencies).toHaveBeenCalled());
  await waitFor(() => expect(screen.getByRole("button", { name: "Check dependencies" })).toBeEnabled());
  expect(useAppStore.getState().pageStatus["deps-scan"]?.tone).toBe(terminal);
  await act(async () => progress({ payload: { phase: "querying-osv", done: 0, total: 1 } }));
  expect(useAppStore.getState().pageStatus["deps-scan"]?.tone).toBe(terminal);
  expect(useAppStore.getState().pageStatus["deps-scan"]?.label).toMatch(terminal === "success" ? /Dependencies checked/ : /Dependency check failed/);
  expect(useScanWorkStore.getState().active).toBeNull();
  stop();
});


test("dependency cancellation during preparation leaves a terminal status", async () => {
  useAppStore.setState({ activeProject: "/project", pageStatus: {} });
  let finish!: () => void;
  vi.mocked(api.setActiveProject).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  vi.spyOn(api, "cancelDependencyScan").mockResolvedValue();
  const scan = vi.spyOn(api, "scanDependencies");
  render(<DepsScanPage />);
  fireEvent.click(screen.getByRole("button", { name: "Check dependencies" }));
  await waitFor(() => expect(finish).toBeDefined());
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  await act(async () => finish());
  await waitFor(() => expect(screen.getByRole("button", { name: "Check dependencies" })).toBeEnabled());
  expect(scan).not.toHaveBeenCalled();
  expect(useScanWorkStore.getState().active).toBeNull();
  expect(useAppStore.getState().pageStatus["deps-scan"]?.tone).toBe("neutral");
  expect(useAppStore.getState().pageStatus["deps-scan"]?.label).toMatch(/cancelled/i);
});

test('dependency group recheck uses the shared scan and honors active ownership', async () => {
  const { dependencyResult } = await import('../../../tests/fixtures/projectHome');
  const receipt=dependencyResult('/project');
  useAppStore.getState().openProject('/project','deps-scan',undefined,receipt);
  const fresh=dependencyResult('/project');fresh.summary.packagesFound=31;
  const scan=vi.spyOn(api,'scanDependencies').mockResolvedValue(fresh);
  render(<DepsScanPage/>);
  const recheck=await screen.findByRole('button',{name:'Recheck dependencies'});
  let ownership:number|null=null;
  await act(async()=>{ownership=acquireScan('source','source-scan','/other');});
  expect(recheck).toBeDisabled();
  await act(async()=>{releaseScan(ownership!);});
  fireEvent.click(recheck);
  expect(await screen.findByText('31')).toBeInTheDocument();
  expect(scan).toHaveBeenCalledTimes(1);
  expect(useScanWorkStore.getState().active).toBeNull();
  expect(useAppStore.getState().pageStatus['deps-scan']?.tone).toBe('success');
});

test.each(['completed','handoff','restored'] as const)('dependency %s receipt counts lockfile inventory occurrences instead of provider queries',async(source)=>{
  const { dependencyResult }=await import('../../../tests/fixtures/projectHome');
  const receipt=dependencyResult('/project');
  receipt.summary.lockfilesFound=['/project/package-lock.json','/project/empty/package-lock.json'];
  receipt.summary.packagesFound=2;
  receipt.summary.packagesQueried=1;
  receipt.dependencies=[
    {ecosystem:'npm',name:'lodash',version:'4.17.20',lockfile:'/project/package-lock.json'},
    {ecosystem:'npm',name:'@qa/worker',version:'',lockfile:'/project/package-lock.json',occurrence:{localWorkspace:true,installPath:'packages/worker',status:'available',paths:[],warnings:[]}},
  ];
  useAppStore.setState({activeProject:'/project',selectedProject:'/project'});
  if(source==='handoff') useAppStore.getState().openProject('/project','deps-scan',undefined,receipt);
  if(source==='restored') {
    vi.mocked(api.listCanonicalRuns).mockResolvedValue([savedDependencyRun]);
    vi.spyOn(api,'loadCanonicalProjection').mockResolvedValue(receipt);
  }
  if(source==='completed') vi.spyOn(api,'scanDependencies').mockResolvedValue(receipt);
  render(<DepsScanPage/>);
  if(source==='completed') fireEvent.click(screen.getByRole('button',{name:'Check dependencies'}));
  if(source==='restored') {
    expect(await screen.findAllByText('(packages unknown)').then(nodes => nodes[0])).toBeInTheDocument();
    expect(api.loadCanonicalProjection).not.toHaveBeenCalled();
    return;
  }
  expect(await screen.findByText('(2 pkgs)')).toBeInTheDocument();
  expect(screen.getByTitle('/project/package-lock.json')).toHaveTextContent('(2 pkgs)');
  expect(screen.getByTitle('/project/empty/package-lock.json')).toHaveTextContent('(0 pkgs)');
});
test('historical dependency receipt without complete inventory marks package counts unknown',async()=>{
  const { dependencyResult }=await import('../../../tests/fixtures/projectHome');
  const receipt=dependencyResult('/project');
  receipt.summary.packagesFound=2;
  useAppStore.getState().openProject('/project','deps-scan',undefined,receipt);
  render(<DepsScanPage/>);
  expect(await screen.findByText('(packages unknown)')).toBeInTheDocument();
});

test('saved source coverage caveats remain visible after a project handoff', async () => {
  const { sourceResult } = await import('../../../tests/fixtures/projectHome');
  const receipt = sourceResult('/project');
  receipt.summary.coverageWarnings = ['Byte budget excluded 12 files', 'Traversal failed for vendor/private'];
  vi.spyOn(api, 'loadSourceRun').mockResolvedValue(receipt);
  useAppStore.getState().openProject('/project', 'source-scan', receipt.runId);
  render(<SourceScanPage />);
  expect(await screen.findByText('Byte budget excluded 12 files')).toBeInTheDocument();
  expect(screen.getByText('Traversal failed for vendor/private')).toBeInTheDocument();
});

test('discovery distinguishes malformed lockfiles from a valid empty lockfile', async () => {
  useAppStore.setState({ activeProject: '/project' });
  vi.spyOn(api, 'findLockfiles').mockResolvedValue([
    { path: '/project/package-lock.json', kind: 'npm', packages: null, parseError: 'Unexpected end of JSON' },
    { path: '/project/empty/package-lock.json', kind: 'npm', packages: 0 },
  ]);
  render(<DepsScanPage />);
  fireEvent.click(screen.getByRole('button', { name: 'Find lockfiles' }));
  expect(await screen.findByText('Unexpected end of JSON')).toBeInTheDocument();
  expect(screen.getByTitle('/project/package-lock.json')).toHaveTextContent('packages unknown');
  expect(screen.getByTitle('/project/empty/package-lock.json')).toHaveTextContent('0 pkgs');
});

test('dependency launches bind the ownership operation ID', async () => {
  const { dependencyResult } = await import('../../../tests/fixtures/projectHome');
  useAppStore.setState({ activeProject: '/project' });
  let finish!: (value: ReturnType<typeof dependencyResult>) => void;
  const scan = vi.spyOn(api, 'scanDependencies').mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  render(<DepsScanPage />);
  fireEvent.click(screen.getByRole('button', { name: 'Check dependencies' }));
  await waitFor(() => expect(scan).toHaveBeenCalled());
  expect(scan).toHaveBeenCalledWith('/project', false, null, useScanWorkStore.getState().active!.operationId);
  await act(async () => finish(dependencyResult('/project')));
});

test('dependency recovery reloads newly saved results without launching work', async () => {
  const { dependencyResult } = await import('../../../tests/fixtures/projectHome');
  const saved = dependencyResult('/project'); saved.summary.packagesFound = 47;
  useAppStore.setState({ activeProject: '/project' });
  const scan = vi.spyOn(api, 'scanDependencies');
  render(<DepsScanPage />);
  await waitFor(() => expect(api.listCanonicalRuns).toHaveBeenCalled());
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([savedDependencyRun]);
  vi.spyOn(api, 'loadCanonicalProjection').mockResolvedValue(saved);
  await act(async () => useScanWorkStore.setState(state => ({ recoveryRevision: state.recoveryRevision + 1 })));
  expect(await screen.findByText('47')).toBeInTheDocument();
  expect(scan).not.toHaveBeenCalled();
});

test('source launch binds the native request to its exact ownership operation', async () => {
  const { sourceResult } = await import('../../../tests/fixtures/projectHome');
  useAppStore.setState({ activeProject: '/project' });
  let finish!: (value: ReturnType<typeof sourceResult>) => void;
  const scan = vi.spyOn(api, 'scanProject').mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  render(<SourceScanPage />);
  await screen.findByText('Project ready');
  fireEvent.click(screen.getByRole('button', { name: 'Run scan' }));
  await waitFor(() => expect(scan).toHaveBeenCalled());
  expect(scan).toHaveBeenCalledWith(expect.objectContaining({ path: '/project' }), useScanWorkStore.getState().active!.operationId);
  await act(async () => finish(sourceResult('/project')));
});

test('source reloads the saved A receipt after completing A, editing B, and returning to A without a backend revision', async () => {
  const { sourceResult } = await import('../../../tests/fixtures/projectHome');
  const saved = sourceResult('/project-a'); saved.summary.filesScanned = 73;
  let completed = false;
  useAppStore.setState({ activeProject: '/project-a', selectedProject: '/project-a' });
  vi.mocked(api.inspectSourceProject).mockImplementation(async path => ({ projectId: path, canonicalPath: path, displayName: path, policy: { status: 'missing' }, lastCompletedRunId: path === '/project-a' && completed ? saved.runId : null, lastOptions: null }));
  const scan = vi.spyOn(api, 'scanProject').mockImplementation(async () => { completed = true; return saved; });
  vi.spyOn(api, 'loadSourceRun').mockResolvedValue(saved);
  vi.spyOn(api, 'scanWorkStatus').mockResolvedValue({ active: null, recent: [] });
  render(<SourceScanPage />);
  await screen.findByText('Project ready');
  fireEvent.click(screen.getByRole('button', { name: 'Run scan' }));
  expect(await screen.findByText('73')).toBeInTheDocument();
  await waitFor(() => expect(screen.getByRole('button', { name: 'Run scan' })).toBeEnabled());
  const revision = useScanWorkStore.getState().recoveryRevision;
  fireEvent.change(screen.getByLabelText('Project folder path'), { target: { value: '/project-b' } });
  await screen.findByText('Project ready');
  expect(screen.queryByText('73')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Project folder path'), { target: { value: '/project-a' } });
  expect(await screen.findByText('73')).toBeInTheDocument();
  expect(api.loadSourceRunMetadata).toHaveBeenCalledWith(saved.runId);
  expect(scan).toHaveBeenCalledTimes(1);
  expect(useScanWorkStore.getState().recoveryRevision).toBe(revision);
});
