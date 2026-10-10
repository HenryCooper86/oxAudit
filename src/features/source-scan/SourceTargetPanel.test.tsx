import { fireEvent, render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { SourceTargetPanel } from "./SourceTargetPanel";
import { createSourceScanOptions } from "../../lib/sourceScanOptions";
const dropped = vi.hoisted(() => ({ select: null as ((path: string) => void) | null }));
vi.mock("./useProjectDrop", () => ({ useProjectDrop: (select: (path: string) => void) => { dropped.select = select; return { dropping: false }; } }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

test("unavailable recent targets retain their path without stale review totals", () => {
  render(<SourceTargetPanel path="" project={null} options={createSourceScanOptions(null)} running={false} cancelling={false} dropping={false} progress={null} rulePackFiles="" onRulePackFilesChange={vi.fn()} onPathChange={vi.fn()} onOptionChange={vi.fn()} onRun={vi.fn()} onCancel={vi.fn()} recentProjects={[{
    projectId: "missing", canonicalPath: "/missing", displayName: "missing",
    lastOpenedAt: "2026-09-07T00:00:00Z", lastCompletedRunId: "old",
    lastCompletedAt: "2026-09-06T00:00:00Z", openFindings: 0, critical: 0, high: 0,
    ...{ countsAvailable: false },
  }]} />);
  expect(screen.getByText("/missing")).toBeInTheDocument();
  expect(screen.getByText("Counts unavailable")).toBeInTheDocument();
  expect(screen.queryByText("0 open")).not.toBeInTheDocument();
  expect(screen.queryByText(/critical\/high/)).not.toBeInTheDocument();
});

test("a drop cannot change a running scan target and current counts do not claim overall percentage", () => {
  const onPathChange = vi.fn();
  render(<SourceTargetPanel path="/repo" project={null} options={createSourceScanOptions(null)} running cancelling={false} dropping={false} progress={{ phase: "scanning", done: 25, total: 100 }} rulePackFiles="" onRulePackFilesChange={vi.fn()} onPathChange={onPathChange} onOptionChange={vi.fn()} onRun={vi.fn()} onCancel={vi.fn()} recentProjects={[]} />);
  dropped.select?.("/replacement");
  expect(onPathChange).not.toHaveBeenCalled();
  expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
  expect(screen.getByRole("textbox", { name: "Project folder path" })).toBeDisabled();
});

test("selecting a recent source target only changes the path", () => {
  const onPathChange = vi.fn();
  const onRun = vi.fn();
  render(<SourceTargetPanel path="" project={null} options={createSourceScanOptions(null)} running={false} cancelling={false} dropping={false} progress={null} rulePackFiles="" onRulePackFilesChange={vi.fn()} onPathChange={onPathChange} onOptionChange={vi.fn()} onRun={onRun} onCancel={vi.fn()} recentProjects={[{
    projectId: "recent", canonicalPath: "/recent", displayName: "recent", lastOpenedAt: "2026-09-07T00:00:00Z", lastCompletedRunId: null, lastCompletedAt: null, openFindings: 0, critical: 0, high: 0,
  }]} />);
  fireEvent.click(screen.getByRole("button", { name: /recent.*Counts unknown/i }));
  expect(onPathChange).toHaveBeenCalledWith("/recent");
  expect(onRun).not.toHaveBeenCalled();
});
