import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { PortfolioPage } from "./Portfolio";
import type { RecentProject, ScanRunDetail, ScanScheduleStatus } from "../lib/types";

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
  runScanNow.mockResolvedValue({
    runId: "abcd1234-0000",
    summary: { totalFindings: 3 },
  } as unknown as ScanRunDetail);
  render(<PortfolioPage />);
  await screen.findByText("service-a");
  await userEvent.click(screen.getByRole("button", { name: /scan now/i }));
  await waitFor(() => expect(runScanNow).toHaveBeenCalledWith("p1", "/work/service-a"));
  await waitFor(() =>
    expect(toast).toHaveBeenCalledWith("success", expect.stringContaining("3 finding(s)")),
  );
});
