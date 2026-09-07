import { act, renderHook, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { api } from "../../lib/api";
import { useReviewChanges } from "./useReviewChanges";
import type { Finding, GitContext, ScanRunDetail } from "../../lib/types";
vi.mock("../../lib/api", () => ({ api: { compareSourceRuns: vi.fn(), inspectSourceGit: vi.fn() } }));
const deferred = <T,>() => { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; };
const finding = (id: string, path = "app.js") => ({ fingerprint: id, filePath: path, observationRunId: "run", diffStatus: "new" } as Finding);
const run = { runId: "run", baselineRunId: "auto", status: "completed", persistence: { status: "saved" }, findings: [finding("auto")], summary: { path: "/a" } } as ScanRunDetail;
const git = { target: "/a", snapshot: { head: "a", branch: "main", indexDigest: "i" }, baseReference: "HEAD", baseCommit: "a", stagedPaths: ["app.js"], unstagedPaths: ["new.js"], changedPaths: ["app.js", "new.js"], inspectedAt: "now", partiallyStaged: false } satisfies GitContext;

test("baseline choices reject stale promises and reset on run/target changes", async () => {
  vi.mocked(api.inspectSourceGit).mockResolvedValue(git);
  const old = deferred<Finding[]>(), next = deferred<Finding[]>();
  vi.mocked(api.compareSourceRuns).mockImplementation((_, id) => id === "old" ? old.promise : next.promise);
  const hook = renderHook(({ target, current }) => useReviewChanges(target, current), { initialProps: { target: "/a", current: run } });
  act(() => hook.result.current.setBaseline("old"));
  await waitFor(() => expect(api.compareSourceRuns).toHaveBeenCalledWith("run", "old"));
  act(() => hook.result.current.setBaseline("next"));
  await act(async () => next.resolve([finding("next")]));
  expect(hook.result.current.findings[0].fingerprint).toBe("next");
  await act(async () => old.resolve([finding("old")]));
  expect(hook.result.current.findings[0].fingerprint).toBe("next");
  hook.rerender({ target: "/b", current: { ...run, runId: "second", baselineRunId: null, findings: [] } });
  expect(hook.result.current.baseline).toBe("automatic");
  expect(hook.result.current.hasBaseline).toBe(false);
});

test("staged and unstaged paths filter current observations only; stale Git restores normal results", async () => {
  vi.mocked(api.inspectSourceGit).mockResolvedValue(git);
  const current = { ...run, findings: [finding("staged"), finding("unstaged", "new.js"), { ...finding("missing"), observationRunId: "old", diffStatus: "notEvaluated" } as Finding] };
  const hook = renderHook(() => useReviewChanges("/a", current));
  await waitFor(() => expect(hook.result.current.git).toEqual(git));
  act(() => hook.result.current.setPathMode("staged"));
  expect(hook.result.current.findings.map(f => f.fingerprint)).toEqual(["staged"]);
  act(() => hook.result.current.setPathMode("unstaged"));
  expect(hook.result.current.findings.map(f => f.fingerprint)).toEqual(["unstaged"]);
  act(() => window.dispatchEvent(new Event("focus")));
  expect(hook.result.current.gitUsable).toBe(false);
  expect(hook.result.current.findings).toEqual(current.findings);
});

test("a stale Git response cannot replace a new target and no Git preserves results", async () => {
  const old = deferred<GitContext>();
  vi.mocked(api.inspectSourceGit).mockImplementation(path => path === "/a" ? old.promise : Promise.reject("No Git checkout"));
  const hook = renderHook(({ target }) => useReviewChanges(target, run), { initialProps: { target: "/a" } });
  hook.rerender({ target: "/b" });
  await act(async () => old.resolve(git));
  await waitFor(() => expect(hook.result.current.gitError).toBeTruthy());
  expect(hook.result.current.git).toBeNull();
  expect(hook.result.current.findings).toEqual(run.findings);
});

test("focus while inspection is pending requires another refresh", async () => {
  const pending = deferred<GitContext>();
  vi.mocked(api.inspectSourceGit).mockReturnValue(pending.promise);
  const hook = renderHook(() => useReviewChanges("/a", run));
  await act(async () => {});
  act(() => window.dispatchEvent(new Event("focus")));
  await act(async () => pending.resolve(git));
  expect(hook.result.current.gitUsable).toBe(false);
});

test("incompatible baseline shows normal results and disables new claims", async () => {
  vi.mocked(api.inspectSourceGit).mockResolvedValue(git);
  vi.mocked(api.compareSourceRuns).mockRejectedValue({ code: "baselineIncompatible", message: "Choose an earlier compatible run", detail: null, retryable: false });
  const hook = renderHook(() => useReviewChanges("/a", run));
  act(() => hook.result.current.setBaseline("incompatible"));
  await waitFor(() => expect(hook.result.current.comparisonError).toContain("compatible"));
  expect(hook.result.current.hasBaseline).toBe(false);
  expect(hook.result.current.findings).toEqual(run.findings);
});

test.each([false, true])("A to B to A starts a fresh inspection lifetime (target changes: %s)", async changeTarget => {
  const pendingB = deferred<GitContext>(), pendingA = deferred<GitContext>();
  vi.mocked(api.inspectSourceGit).mockResolvedValueOnce(git).mockReturnValueOnce(pendingB.promise).mockReturnValue(pendingA.promise);
  vi.mocked(api.compareSourceRuns).mockResolvedValue([finding("explicit")]);
  const hook = renderHook(({ target, current }) => useReviewChanges(target, current), { initialProps: { target: "/a", current: run } });
  await waitFor(() => expect(hook.result.current.gitUsable).toBe(true));
  act(() => { hook.result.current.setBaseline("chosen"); });
  await waitFor(() => expect(hook.result.current.findings[0].fingerprint).toBe("explicit"));
  act(() => hook.result.current.setPathMode("staged"));
  hook.rerender({ target: changeTarget ? "/b" : "/a", current: { ...run, runId: "b" } });
  hook.rerender({ target: "/a", current: run });
  expect(hook.result.current.baseline).toBe("automatic");
  expect(hook.result.current.pathMode).toBe("all");
  expect(hook.result.current.gitUsable).toBe(false);
  expect(hook.result.current.git).toBeNull();
  expect(hook.result.current.findings).toEqual(run.findings);
  await act(async () => pendingB.resolve({ ...git, target: "/b" }));
  expect(hook.result.current.gitUsable).toBe(false);
  await act(async () => pendingA.resolve({ ...git, stagedPaths: ["changed.js"] }));
  expect(hook.result.current.gitUsable).toBe(true);
  expect(hook.result.current.git?.stagedPaths).toEqual(["changed.js"]);
});
