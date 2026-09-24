import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { SeverityTrend } from "./SeverityTrend";
import type { ScanRunSummary } from "../../lib/types";

const run = (overrides: Partial<ScanRunSummary> = {}): ScanRunSummary => ({
  runId: "run-1",
  projectId: "project-1",
  status: "completed",
  startedAt: "2026-09-20T10:00:00Z",
  completedAt: "2026-09-20T10:00:07Z",
  totalFindings: 3,
  newFindings: 2,
  resolvedFindings: 1,
  severityCounts: { critical: 1, high: 1, medium: 0, low: 0, info: 1 },
  ...overrides,
});

test("a stored history plots one column per completed run with its mix", () => {
  render(
    <SeverityTrend
      runs={[
        run({
          runId: "newer",
          completedAt: "2026-09-21T10:00:07Z",
          severityCounts: { critical: 0, high: 2, medium: 0, low: 0, info: 0 },
        }),
        run({ runId: "older", severityCounts: { critical: 1, high: 1, medium: 0, low: 0, info: 1 } }),
      ]}
    />,
  );
  const chart = screen.getByRole("img", { name: /2 most recent completed runs/i });
  expect(chart.querySelectorAll("g[role='listitem']")).toHaveLength(2);
  // The legend and summary line describe the LATEST run, not the oldest.
  expect(screen.getByText("2 high")).toBeInTheDocument();
  expect(screen.getByText(/2 new · 1 resolved/)).toBeInTheDocument();
});

test("unfinished runs are excluded and never plotted as clean columns", () => {
  render(
    <SeverityTrend
      runs={[
        run({ runId: "running", status: "running", completedAt: null }),
        run({ runId: "done" }),
      ]}
    />,
  );
  const chart = screen.getByRole("img", { name: /1 most recent completed run/i });
  expect(chart.querySelectorAll("g[role='listitem']")).toHaveLength(1);
  // The unfinished run's presence is acknowledged, not silently dropped.
  expect(screen.queryByText(/no completed runs/i)).not.toBeInTheDocument();
});

test("a project with no stored runs says so instead of drawing an empty chart", () => {
  render(<SeverityTrend runs={[]} />);
  expect(screen.getByText(/no stored runs yet/i)).toBeInTheDocument();
  expect(screen.queryByRole("img")).not.toBeInTheDocument();
});

test("runs that never completed say so rather than implying a clean trend", () => {
  render(<SeverityTrend runs={[run({ runId: "running", status: "running", completedAt: null })]} />);
  expect(screen.getByText(/no completed runs yet/i)).toBeInTheDocument();
  expect(screen.getByText(/unfinished scans carry no counts to plot/i)).toBeInTheDocument();
  expect(screen.queryByRole("img")).not.toBeInTheDocument();
});
