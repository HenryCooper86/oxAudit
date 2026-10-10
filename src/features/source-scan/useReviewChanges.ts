import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../lib/api";
import { normalizeCommandError } from "../../lib/commandError";
import type { Finding, GitContext, ScanRunDetail } from "../../lib/types";

export type GitPathMode = "all" | "changed" | "staged" | "unstaged";
const EMPTY: Finding[] = [];
interface Choices { key: string; generation: number; baseline: string; baseInput: string; requestedBase: string; pathMode: GitPathMode; refresh: number }

export function useReviewChanges(target: string, run: ScanRunDetail | null, paged = false) {
  const key = JSON.stringify([target, run?.runId]);
  const defaults = (generation: number): Choices => ({ key, generation, baseline: "automatic", baseInput: "HEAD", requestedBase: "HEAD", pathMode: "all", refresh: 0 });
  const [stored, setChoices] = useState<Choices>(() => defaults(0));
  const choices = stored.key === key ? stored : defaults(stored.generation + 1);
  const { generation, baseline, baseInput, requestedBase, pathMode, refresh } = choices;
  const update = (patch: Partial<Choices>) => setChoices(current =>
    current.generation === generation && current.key === key ? { ...current, ...patch } : current,
  );
  const [comparison, setComparison] = useState<{ key: string; generation: number; baseline: string; run: ScanRunDetail; findings?: Finding[]; error?: string } | null>(null);
  const invalidation = useRef(0);
  const [inspection, setInspection] = useState<{ key: string; generation: number; reference: string; refresh: number; context?: GitContext; error?: string; stale: boolean } | null>(null);

  // A reusable target/run key is not a request lifetime. Reset during render so
  // even A -> B -> A cannot expose cached choices or Git paths for one frame.
  if (stored.key !== key) {
    setChoices(choices);
    setComparison(null);
    setInspection(null);
  }

  useEffect(() => {
    if (paged || !run || baseline === "automatic" || run.status !== "completed" || run.persistence.status !== "saved") return;
    let disposed = false;
    void Promise.resolve().then(() => api.compareSourceRuns(run.runId, baseline)).then(
      findings => { if (!disposed) setComparison({ key, generation, baseline, run, findings }); },
      error => { if (!disposed) setComparison({ key, generation, baseline, run, error: normalizeCommandError(error).message }); },
    );
    return () => { disposed = true; };
  }, [key, generation, baseline, run, paged]);

  useEffect(() => {
    if (!target) return;
    let disposed = false;
    const epoch = invalidation.current;
    void Promise.resolve().then(() => api.inspectSourceGit(target, requestedBase)).then(
      context => { if (!disposed) setInspection({ key, generation, reference: requestedBase, refresh, context, stale: epoch !== invalidation.current }); },
      error => { if (!disposed) setInspection({ key, generation, reference: requestedBase, refresh, error: typeof error === "string" ? error : "Git context unavailable. Full scans remain available.", stale: false }); },
    );
    return () => { disposed = true; };
  }, [key, generation, target, requestedBase, refresh]);

  useEffect(() => {
    const invalidate = () => {
      invalidation.current++;
      setInspection(value => value ? { ...value, stale: true } : value);
    };
    window.addEventListener("focus", invalidate);
    const timer = window.setInterval(invalidate, 60_000);
    return () => { window.removeEventListener("focus", invalidate); window.clearInterval(timer); };
  }, []);

  const selected = comparison?.key === key && comparison.generation === generation && comparison.baseline === baseline && comparison.run === run ? comparison : null;
  const comparing = baseline !== "automatic";
  const comparisonReady = paged || !comparing || Boolean(selected?.findings);
  const allFindings = selected?.findings ?? run?.findings ?? EMPTY;
  const baselineId = comparing && (paged || selected?.findings) ? baseline : run?.baselineRunId;
  const hasBaseline = Boolean(baselineId) && comparisonReady;
  const current = inspection?.key === key && inspection.generation === generation && inspection.reference === requestedBase && inspection.refresh === refresh ? inspection : null;
  const git = current?.context ?? null;
  const gitUsable = Boolean(git && !current?.stale && baseInput === requestedBase);
  const findings = useMemo(() => {
    if (!gitUsable || !git || pathMode === "all") return allFindings;
    const paths = new Set(pathMode === "changed" ? git.changedPaths : pathMode === "staged" ? git.stagedPaths : git.unstagedPaths);
    return allFindings.filter(finding => finding.observationRunId === run?.runId && paths.has(finding.filePath));
  }, [allFindings, gitUsable, git, pathMode, run?.runId]);
  const counts = useMemo(() => {
    const result = { new: 0, unchanged: 0, resolved: 0, notEvaluated: 0 };
    for (const finding of allFindings) if (finding.diffStatus) result[finding.diffStatus]++;
    return result;
  }, [allFindings]);
  return {
    baseline, baselineId, hasBaseline, comparisonReady, comparisonError: selected?.error ?? null,
    comparisonLoading: !paged && comparing && !selected, counts, allFindings, findings,
    setBaseline: (value: string) => update({ baseline: value }),
    baseInput, setBaseInput: (value: string) => update({ baseInput: value }),
    pathMode, setPathMode: (value: GitPathMode) => update({ pathMode: value }),
    filePaths: gitUsable && git && pathMode !== "all" ? (pathMode === "changed" ? git.changedPaths : pathMode === "staged" ? git.stagedPaths : git.unstagedPaths) : null,
    git, gitUsable, gitLoading: Boolean(target && !current), gitError: current?.error ?? null,
    refreshGit: () => update({ requestedBase: baseInput, refresh: refresh + 1 }),
  };
}
export type ReviewChangesState = ReturnType<typeof useReviewChanges>;
