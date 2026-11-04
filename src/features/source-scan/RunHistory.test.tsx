import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { RunHistory } from "./RunHistory";
import type { ScanRunSummary } from "../../lib/types";

function history(projectId = "project-a"): ScanRunSummary[] {
  return Array.from({ length: 50 }, (_, i) => ({
    runId: `${projectId}-${i + 1}`, projectId, status: "completed",
    startedAt: new Date(Date.UTC(2026, 10, 4, 0, 50 - i)).toISOString(),
    completedAt: new Date(Date.UTC(2026, 10, 4, 0, 50 - i)).toISOString(),
    totalFindings: i + 1, newFindings: i + 1, resolvedFindings: 0,
    severityCounts: { critical: 0, high: i + 1, medium: 0, low: 0, info: 0 },
  }));
}

test("long histories stay compact while retaining an older selection and access to every run", async () => {
  const user = userEvent.setup(), onSelect = vi.fn();
  const runs = history();
  const { rerender } = render(<RunHistory runs={runs} selectedRunId="project-a-50" loadingRunId={null} running={false} onSelect={onSelect} />);
  const region = within(screen.getByRole("region", { name: "Run history" }));
  expect(region.getAllByRole("button", { name: /findings/ })).toHaveLength(3);
  expect(region.getByRole("button", { name: /50 findings/ })).toHaveAttribute("aria-current", "true");
  const toggle = region.getByRole("button", { name: "Show all 50 runs" });
  expect(toggle).toHaveAttribute("aria-expanded", "false");
  await user.click(toggle);
  expect(region.getAllByRole("button", { name: /findings/ })).toHaveLength(50);
  await user.click(region.getByRole("button", { name: /25 findings/ }));
  expect(onSelect).toHaveBeenCalledWith("project-a-25");
  rerender(<RunHistory runs={runs} selectedRunId="project-a-25" loadingRunId={null} running={false} onSelect={onSelect} />);
  await user.click(region.getByRole("button", { name: "Show fewer runs" }));
  expect(toggle).toHaveFocus();
  expect(region.getAllByRole("button", { name: /findings/ })).toHaveLength(3);
  expect(region.getByRole("button", { name: /25 findings/ })).toHaveAttribute("aria-current", "true");
});

test("changing projects starts with compact history even if the previous one was expanded", async () => {
  const user = userEvent.setup();
  const props = { selectedRunId: null, loadingRunId: null, running: false, onSelect: vi.fn() };
  const { rerender } = render(<RunHistory {...props} runs={history()} />);
  await user.click(screen.getByRole("button", { name: "Show all 50 runs" }));
  rerender(<RunHistory {...props} runs={history("project-b")} />);
  expect(screen.getByRole("button", { name: "Show all 50 runs" })).toHaveAttribute("aria-expanded", "false");
  expect(screen.getAllByRole("button", { name: /findings/ })).toHaveLength(3);
});
