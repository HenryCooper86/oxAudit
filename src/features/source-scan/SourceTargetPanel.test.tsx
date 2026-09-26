import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { SourceTargetPanel } from "./SourceTargetPanel";
import { createSourceScanOptions } from "../../lib/sourceScanOptions";
vi.mock("./useProjectDrop", () => ({ useProjectDrop: () => ({ dropping: false }) }));
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
