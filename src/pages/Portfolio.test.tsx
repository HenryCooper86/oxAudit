import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { PortfolioPage } from "./Portfolio";
import { sourceResult } from "../../tests/fixtures/projectHome";
import type { RecentProject, ScanScheduleStatus } from "../lib/types";

const listen = vi.fn().mockResolvedValue(() => {});
vi.mock("@tauri-apps/api/event", () => ({
  listen: (...args: unknown[]) => listen(...args),
}));

const listSourceProjects = vi.fn();
const listScanSchedules = vi.fn();
const setScanSchedule = vi.fn();
const removeScanSchedule = vi.fn();
const runScanNow = vi.fn();
vi.mock("../lib/api", () => ({
  api: {
    listSourceProjects: (...args: unknown[]) => listSourceProjects(...args),
    listScanSchedules: (...args: unknown[]) => listScanSchedules(...args),
    setScanSchedule: (...args: unknown[]) => setScanSchedule(...args),
    removeScanSchedule: (...args: unknown[]) => removeScanSchedule(...args),
    runScanNow: (...args: unknown[]) => runScanNow(...args),
  },
}));

const toast = vi.fn<(kind: string, message: string) => void>();
vi.mock("../lib/stores", () => ({
  useToastStore: (selector: (state: { push: typeof toast }) => unknown) =>
    selector({ push: toast }),
}));

const project = (overrides: Partial<RecentProject> = {}): RecentProject => ({
  projectId: "p1",
  canonicalPath: "/work/service-a",
  displayName: "service-a",
  lastOpenedAt: "2026-09-24T00:00:00Z",
  lastCompletedRunId: "run-1",
  lastCompletedAt: "2026-09-23T10:00:00Z",
  countsAvailable: true,
  openFindings: 4,
  critical: 1,
  high: 2,
  ...overrides,
});

const schedule = (overrides: Partial<ScanScheduleStatus> = {}): ScanScheduleStatus => ({
  projectId: "p1",
  canonicalPath: "/work/service-a",
  displayName: "service-a",
  intervalHours: 24,
  enabled: true,
  lastStartedAt: "2026-09-23T10:00:00Z",
  nextDueAt: "2026-09-24T10:00:00Z",
  ...overrides,
});

test("projects beyond the first fifty remain accessible and schedulable", async () => {
  const projects = Array.from({ length: 53 }, (_, index) => project({ projectId: `p${index}`, displayName: `service-${index}`, canonicalPath: `/work/service-${index}` }));
  listSourceProjects.mockImplementation((limit: number, offset = 0) => Promise.resolve(projects.slice(offset, offset + limit)));
  listScanSchedules.mockResolvedValue([]);
  setScanSchedule.mockResolvedValue({});
  render(<PortfolioPage />);
  await screen.findByText('service-0');
  expect(screen.queryByText('service-50')).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Next page of projects' }));
  await screen.findByText('service-52');
  expect(screen.queryByText('service-0')).not.toBeInTheDocument();
  const row = screen.getByText('service-52').closest('li')!;
  await userEvent.click(within(row).getByRole('button', { name: /schedule daily/i }));
  await waitFor(() => expect(setScanSchedule).toHaveBeenCalledWith('p52', '/work/service-52', 'service-52', 24, true));
  await userEvent.click(screen.getByRole('button', { name: 'Previous page of projects' }));
  await screen.findByText('service-0');
});

test("a failed initial portfolio load can be retried in place", async () => {
  listSourceProjects.mockRejectedValueOnce(new Error('Temporary outage')).mockResolvedValue([project()]);
  listScanSchedules.mockResolvedValue([]);
  render(<PortfolioPage />);
  await screen.findByText(/Temporary outage/);
  await userEvent.click(screen.getByRole('button', { name: 'Retry loading portfolio' }));
  await screen.findByText('service-a');
  expect(screen.queryByText(/Temporary outage/)).not.toBeInTheDocument();
});

test("a failed later portfolio page retries the same offset without showing earlier projects", async () => {
  const first = Array.from({ length: 51 }, (_, index) => project({ projectId: `p${index}`, displayName: `first-${index}` }));
  listSourceProjects.mockResolvedValueOnce(first)
    .mockRejectedValueOnce(new Error('Page temporarily unavailable'))
    .mockResolvedValue([project({ projectId: 'older', displayName: 'older-project' })]);
  listScanSchedules.mockResolvedValue([]);
  render(<PortfolioPage />);
  await screen.findByText('first-0');
  await userEvent.click(screen.getByRole('button', { name: 'Next page of projects' }));
  await screen.findByText(/Page temporarily unavailable/);
  expect(screen.queryByText('first-0')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Previous page of projects' })).toBeEnabled();
  await userEvent.click(screen.getByRole('button', { name: 'Retry loading portfolio' }));
  await screen.findByText('older-project');
  expect(listSourceProjects).toHaveBeenLastCalledWith(51, 50);
});

test("each project stays busy until its own schedule write completes", async () => {
  listSourceProjects.mockResolvedValue([project(), project({ projectId: "p2", displayName: "service-b", canonicalPath: "/work/service-b" })]);
  listScanSchedules.mockResolvedValue([]);
  const pending = new Map<string, () => void>();
  setScanSchedule.mockImplementation((id: string) => new Promise<void>(resolve => { pending.set(id, resolve); }));
  render(<PortfolioPage />);
  await screen.findByText("service-a");
  const [first, second] = screen.getAllByRole("listitem").map(row => within(row));
  await userEvent.click(first.getByRole("button", { name: /schedule daily/i }));
  expect(first.getByRole("button", { name: /schedule daily/i })).toBeDisabled();
  expect(second.getByRole("button", { name: /schedule daily/i })).toBeEnabled();
  await userEvent.click(second.getByRole("button", { name: /schedule daily/i }));
  expect(first.getByRole("button", { name: /schedule daily/i })).toBeDisabled();
  expect(second.getByRole("button", { name: /schedule daily/i })).toBeDisabled();
  await act(async () => pending.get("p2")!());
  expect(first.getByRole("button", { name: /schedule daily/i })).toBeDisabled();
  expect(second.getByRole("button", { name: /schedule daily/i })).toBeEnabled();
  await act(async () => pending.get("p1")!());
  expect(first.getByRole("button", { name: /schedule daily/i })).toBeEnabled();
});

test("a superseded schedule refresh keeps controls locked until fresh values arrive", async () => {
  const secondProject = project({ projectId: "p2", displayName: "service-b", canonicalPath: "/work/service-b" });
  listSourceProjects.mockResolvedValue([project(), secondProject]);
  let resolveFirst!: (value: ScanScheduleStatus[]) => void;
  let resolveSecond!: (value: ScanScheduleStatus[]) => void;
  listScanSchedules.mockResolvedValueOnce([schedule()])
    .mockReturnValueOnce(new Promise<ScanScheduleStatus[]>(done => { resolveFirst = done; }))
    .mockReturnValueOnce(new Promise<ScanScheduleStatus[]>(done => { resolveSecond = done; }))
    .mockResolvedValue([schedule({ intervalHours: 168, enabled: false })]);
  setScanSchedule.mockReset().mockResolvedValue({});
  render(<PortfolioPage />);
  await screen.findByText("service-a");
  const [first, second] = screen.getAllByRole("listitem").map(row => within(row));
  await userEvent.selectOptions(first.getByRole("combobox"), "168");
  await userEvent.click(second.getByRole("button", { name: /schedule daily/i }));
  await act(async () => resolveFirst([schedule({ intervalHours: 168 })]));
  expect(first.getByRole("switch", { name: /rescheduling/i })).toBeDisabled();
  await act(async () => resolveSecond([schedule({ intervalHours: 168 }), schedule({ projectId: "p2" })]));
  expect(first.getByRole("combobox")).toHaveValue("168");
  await userEvent.click(first.getByRole("switch", { name: /rescheduling/i }));
  expect(setScanSchedule).toHaveBeenLastCalledWith("p1", "/work/service-a", "service-a", 168, false);
});

test("the portfolio shows evidence and staleness per project", async () => {
  listSourceProjects.mockResolvedValue([project()]);
  listScanSchedules.mockResolvedValue([]);
  render(<PortfolioPage />);
  expect(await screen.findByText("service-a")).toBeInTheDocument();
  expect(screen.getByText(/4 open/)).toBeInTheDocument();
  expect(screen.getByText(/\(1 critical \/ 2 high\)/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /schedule daily/i })).toBeInTheDocument();
  expect(screen.getByText(/scheduled scans run only while oxaudit is open/i)).toBeInTheDocument();
});

test("scheduling a project saves the cadence and shows the next fire time", async () => {
  listSourceProjects.mockResolvedValue([project()]);
  listScanSchedules
    .mockResolvedValueOnce([])
    .mockResolvedValue([schedule()]);
  setScanSchedule.mockResolvedValue({});
  render(<PortfolioPage />);
  await screen.findByText("service-a");
  await userEvent.click(screen.getByRole("button", { name: /schedule daily/i }));
  await waitFor(() =>
    expect(setScanSchedule).toHaveBeenCalledWith("p1", "/work/service-a", "service-a", 24, true),
  );
  expect(await screen.findByText(/next rescan/i)).toBeInTheDocument();
  expect(screen.getByRole("switch", { name: /rescheduling/i })).toBeChecked();
});

test("an existing schedule can be unscheduled and re-disabled", async () => {
  listSourceProjects.mockResolvedValue([project()]);
  listScanSchedules
    .mockResolvedValueOnce([schedule()])
    .mockResolvedValueOnce([schedule({ enabled: false, nextDueAt: null })])
    .mockResolvedValue([]);
  render(<PortfolioPage />);
  await screen.findByText(/next rescan/i);
  await userEvent.click(screen.getByRole("switch", { name: /rescheduling/i }));
  await waitFor(() => expect(setScanSchedule).toHaveBeenCalledWith("p1", "/work/service-a", "service-a", 24, false));
  expect(await screen.findByRole("switch", { name: /^off$/i })).not.toBeChecked();
  await userEvent.click(screen.getByRole("button", { name: /unschedule/i }));
  await waitFor(() => expect(removeScanSchedule).toHaveBeenCalledWith("p1"));
  expect(await screen.findByRole("button", { name: /schedule daily/i })).toBeInTheDocument();
});

test("scan now runs through the scheduler path and reports the run", async () => {
  listSourceProjects.mockResolvedValue([project()]);
  listScanSchedules.mockResolvedValue([]);
  const completed = sourceResult();
  completed.runId = "abcd1234-0000";
  completed.summary.totalFindings = 3;
  runScanNow.mockResolvedValue(completed);
  render(<PortfolioPage />);
  await screen.findByText("service-a");
  await userEvent.click(screen.getByRole("button", { name: /scan now/i }));
  await waitFor(() => expect(runScanNow).toHaveBeenCalledWith("p1", "/work/service-a"));
  await waitFor(() =>
    expect(toast).toHaveBeenCalledWith("success", expect.stringContaining("3 finding(s)")),
  );
});

test("unavailable finding counts are not presented as zero open findings", async () => {
  listSourceProjects.mockResolvedValue([project({ countsAvailable: false, openFindings: 0, critical: 0, high: 0 })]);
  listScanSchedules.mockResolvedValue([]);
  render(<PortfolioPage />);
  await screen.findByText("service-a");
  expect(screen.getByText(/finding counts unavailable/i)).toBeInTheDocument();
  expect(screen.queryByText(/0 open/i)).not.toBeInTheDocument();
});

test("unsaved scans are reported explicitly instead of claiming durable success", async () => {
  listSourceProjects.mockResolvedValue([project()]);
  listScanSchedules.mockResolvedValue([]);
  runScanNow.mockResolvedValue({ ...sourceResult(), persistence: { status: "notSaved", retryToken: "retry" } });
  toast.mockClear();
  render(<PortfolioPage />);
  await screen.findByText("service-a");
  await userEvent.click(screen.getByRole("button", { name: /scan now/i }));
  await waitFor(() => expect(toast).toHaveBeenCalledWith("error", expect.stringMatching(/not saved/i)));
  expect(toast).not.toHaveBeenCalledWith("success", expect.anything());
});

test("a delayed portfolio refresh cannot undo a newly saved schedule", async () => {
  let receive!: (event: { payload: { projectId: string; ok: boolean; findings: number; error: null } }) => void;
  listen.mockImplementation((_name, handler) => { receive = handler; return Promise.resolve(() => {}); });
  listSourceProjects.mockResolvedValue([project()]);
  let release!: (schedules: ScanScheduleStatus[]) => void;
  listScanSchedules.mockResolvedValueOnce([])
    .mockReturnValueOnce(new Promise((resolve) => { release = resolve; }))
    .mockResolvedValue([schedule()]);
  setScanSchedule.mockResolvedValue({});
  render(<PortfolioPage />);
  await screen.findByText("service-a");
  await act(async () => receive({ payload: { projectId: "p1", ok: true, findings: 0, error: null } }));
  await userEvent.click(screen.getByRole("button", { name: /schedule daily/i }));
  await screen.findByText(/next rescan/i);
  await act(async () => release([]));
  expect(screen.getByText(/next rescan/i)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /schedule daily/i })).not.toBeInTheDocument();
});

test("a late schedule subscription is released after the portfolio unmounts", async () => {
  listSourceProjects.mockResolvedValue([]);
  listScanSchedules.mockResolvedValue([]);
  let resolve!: (stop: () => void) => void;
  listen.mockReturnValue(new Promise((done) => { resolve = done; }));
  const stop = vi.fn();
  const view = render(<PortfolioPage />);
  view.unmount();
  await act(async () => resolve(stop));
  expect(stop).toHaveBeenCalledOnce();
});

test("structured command errors are shown by message, never as [object Object]", async () => {
  const commandError = (message: string) => ({ code: "persistenceUnavailable", message, detail: null, retryable: true });
  listSourceProjects.mockReset().mockRejectedValueOnce(commandError("Project index is locked")).mockResolvedValue([project()]);
  listScanSchedules.mockResolvedValue([]);
  runScanNow.mockReset().mockRejectedValue(commandError("Scanner is busy"));
  toast.mockClear();
  render(<PortfolioPage />);
  await screen.findByText(/Project index is locked/);
  expect(screen.queryByText(/object Object/)).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Retry loading portfolio" }));
  await screen.findByText("service-a");
  await userEvent.click(screen.getByRole("button", { name: /scan now/i }));
  await waitFor(() => expect(toast).toHaveBeenCalledWith("error", "service-a: scan failed — Scanner is busy"));
});
