import type { JSX } from "react";
import { Button, Select } from "../../components/ui";
import type { ScanRunDetail, ScanRunSummary } from "../../lib/types";
import type { GitPathMode, ReviewChangesState } from "./useReviewChanges";

export function ReviewChangesPanel({ review, run, runs, newOnly, onNewOnly }: {
  review: ReviewChangesState; run: ScanRunDetail | null; runs: ScanRunSummary[];
  newOnly: boolean; onNewOnly: (value: boolean) => void;
}): JSX.Element {
  const evidence = run?.summary.gitContext;
  const revision = evidence?.before;
  const eligible = runs.filter(candidate => candidate.status === "completed" && candidate.runId !== run?.runId && candidate.completedAt && run && Date.parse(candidate.completedAt) < Date.parse(run.startedAt));
  return <section aria-label="Review changes" className="space-y-3 rounded-sm border border-border bg-surface-secondary p-4 text-[12px] text-text-secondary">
    <div className="flex flex-wrap items-center gap-3">
      <h2 className="text-[13px] font-semibold text-text-primary">Review changes</h2>
      <span>Full working-tree scans · filters change the view only</span>
    </div>
    {run && <>
      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2">Saved baseline
          <Select aria-label="Saved baseline" value={review.baseline} disabled={run.persistence.status !== "saved" || run.status !== "completed"} onChange={e => review.setBaseline(e.target.value)} variant="compact">
            <option value="automatic">Automatic baseline</option>
            {eligible.map(candidate => <option key={candidate.runId} value={candidate.runId}>{new Date(candidate.completedAt!).toLocaleString()} · {candidate.runId.slice(0, 8)}</option>)}
          </Select>
        </label>
        <label className="flex items-center gap-2 font-medium text-text-primary"><input type="checkbox" checked={newOnly && review.hasBaseline} disabled={!review.hasBaseline} onChange={e => onNewOnly(e.target.checked)} />New since baseline</label>
      </div>
      {review.comparisonLoading ? <p role="status">Comparing saved runs… Showing automatic results until comparison completes.</p>
        : review.comparisonError ? <p role="alert" className="text-status-error">{review.comparisonError} Showing automatic results.</p>
        : review.hasBaseline ? <p>Baseline {review.baselineId?.slice(0, 8)}: {review.counts.new} new · {review.counts.unchanged} unchanged · {review.counts.resolved} resolved · {review.counts.notEvaluated} not evaluated. Review states and scope views remain independent.</p>
        : <p>No compatible saved baseline for this run. Findings are observed results; no claim that a commit introduced them.</p>}
      <p>Run revision: <span className="selectable font-mono">{revision?.head ?? "unavailable"}</span>{revision?.branch ? ` (${revision.branch})` : ""}. {evidence?.contextChanged === true ? "Checkout/index context changed during this scan." : evidence?.contextChanged === false ? "Checkout/index metadata matched before and after scanning; this is not an atomic Git snapshot." : "Revision consistency unavailable."}</p>
      <p>Coverage: {run.summary.filesScanned} files scanned · {run.summary.filesSkipped} skipped. Deleted or unscanned files remain not evaluated. Per-artifact content hashes are the scan evidence.</p>
    </>}
    <div className="flex flex-wrap items-end gap-3">
      <label className="grid gap-1">Git base reference<input aria-label="Git base reference" value={review.baseInput} onChange={e => review.setBaseInput(e.target.value)} className="w-44 rounded-sm border border-border bg-surface-primary px-2 py-1.5 text-text-primary" /></label>
      <Button variant="outline" size="md" onClick={review.refreshGit} disabled={review.gitLoading}>Refresh Git</Button>
      <label className="grid gap-1">Paths in findings view<Select aria-label="Git path mode" value={review.pathMode} onChange={e => review.setPathMode(e.target.value as GitPathMode)} variant="compact">
        <option value="all">All files</option>
        <option value="changed" disabled={!review.gitUsable}>Changes against base + working tree</option>
        <option value="staged" disabled={!review.gitUsable}>Staged paths · current working-tree content</option>
        <option value="unstaged" disabled={!review.gitUsable}>Unstaged / untracked paths</option>
      </Select></label>
    </div>
    {review.gitLoading ? <p role="status">Inspecting local Git context…</p> : review.gitError ? <p>{review.gitError}</p> : review.git && <>
      <p>Current checkout: {review.git.snapshot.branch ?? "detached HEAD"} · <span className="selectable font-mono">{review.git.snapshot.head}</span></p>
      <p>Base {review.git.baseReference}: merge base <span className="selectable font-mono">{review.git.baseCommit}</span> · {review.git.changedPaths.length} changed paths · {review.git.stagedPaths.length} staged · {review.git.unstagedPaths.length} unstaged/untracked.</p>
      <p>Paths inspected {new Date(review.git.inspectedAt).toLocaleTimeString()}. Refresh after editing or staging. Raw working-tree bytes are compared without Git clean filters; attributes may produce additional changed paths.</p>
      {revision && (revision.head !== review.git.snapshot.head || revision.indexDigest !== review.git.snapshot.indexDigest) && <p>Current checkout/index differs from this run’s captured context. Findings still describe the saved run.</p>}
      {!review.gitUsable && <p role="status">Git context is stale. Refresh Git to enable path filtering. Normal results are visible.</p>}
      {review.git.partiallyStaged && <p className="font-medium text-text-primary">Partially staged files detected. Staged paths show scanned working-tree content, including unstaged edits.</p>}
      {review.pathMode === "staged" && <p>The index content was not scanned. Every source scan reads the full current working tree.</p>}
      {review.gitUsable && review.git.changedPaths.length === 0 && <p>No Git changes in this target. This is a path view, not evidence that the project is clean.</p>}
    </>}
  </section>;
}
