import { render, screen, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { api } from "../../lib/api";
import type { GitContext, ScanRunDetail } from "../../lib/types";
import { ReviewChangesPanel } from "./ReviewChangesPanel";
import { useReviewChanges } from "./useReviewChanges";
vi.mock("../../lib/api", () => ({ api: { inspectSourceGit: vi.fn(), compareSourceRuns: vi.fn() } }));
const run = { runId: "run", baselineRunId: null, status: "completed", persistence: { status: "saved" }, findings: [], summary: { path: "/a", filesScanned: 2, filesSkipped: 1 } } as unknown as ScanRunDetail;
function Harness() { const review = useReviewChanges("/a", run); return <ReviewChangesPanel review={review} run={run} runs={[]} newOnly={false} onNewOnly={() => {}} />; }
test("first and legacy runs disclose missing baseline/revision and coverage", async () => {
  vi.mocked(api.inspectSourceGit).mockRejectedValue("No Git checkout");
  render(<Harness />);
  expect(screen.getByRole("checkbox", { name: "New since baseline" })).toBeDisabled();
  expect(screen.getByText(/No compatible saved baseline/)).toBeInTheDocument();
  expect(screen.getByText("unavailable")).toBeInTheDocument();
  expect(screen.getByText(/2 files scanned · 1 skipped/)).toBeInTheDocument();
  await waitFor(() => expect(screen.getByText("No Git checkout")).toBeInTheDocument());
});
test("empty Git changes never claim a clean project", async () => {
  vi.mocked(api.inspectSourceGit).mockResolvedValue({ target: "/a", snapshot: { branch: "main", head: "abcdef", indexDigest: "index" }, baseReference: "HEAD", baseCommit: "abcdef", changedPaths: [], stagedPaths: [], unstagedPaths: [], partiallyStaged: false, inspectedAt: "2026-09-07T00:00:00Z" } satisfies GitContext);
  render(<Harness />);
  await waitFor(() => expect(screen.getByText(/No Git changes in this target/)).toBeInTheDocument());
  expect(screen.getByRole("option", { name: "Staged paths · current working-tree content" })).toBeInTheDocument();
});

test("partially staged files disclose that working-tree edits are included", async () => {
  vi.mocked(api.inspectSourceGit).mockResolvedValue({ target: "/a", snapshot: { branch: "main", head: "abcdef", indexDigest: "index" }, baseReference: "HEAD", baseCommit: "abcdef", changedPaths: ["app.js"], stagedPaths: ["app.js"], unstagedPaths: ["app.js"], partiallyStaged: true, inspectedAt: "2026-09-07T00:00:00Z" } satisfies GitContext);
  render(<Harness />);
  await waitFor(() => expect(screen.getByText(/Partially staged files detected/)).toBeInTheDocument());
  expect(screen.getByText(/including unstaged edits/)).toBeInTheDocument();
});
