import { api } from "../../lib/api";
import { normalizedTarget } from "../../lib/durableRuns";
import type { CanonicalRun } from "../../lib/types";

/** Read stored evidence by canonical run identity, retaining a failed latest attempt separately. */
export async function readSavedScanReceipt<T extends { runId?: string }>(kind: "image" | "history", target: string, preferredRunId?: string | null): Promise<{
  target: string; attempt: CanonicalRun | null; receipt: CanonicalRun | null; data: T | null; loadError: string | null;
}> {
  const runs = (await api.listCanonicalRuns(kind)).filter(run => run.kind === kind)
    .sort((left, right) => right.updatedAtMs - left.updatedAtMs || right.id.localeCompare(left.id));
  const resolvedTarget = target || runs[0]?.targetLabel || "";
  const matching = runs.filter(run => normalizedTarget(run.targetLabel) === normalizedTarget(resolvedTarget) || run.id === preferredRunId);
  const attempt = matching[0] ?? null;
  const receipt = matching.find(run => run.state === "completed" || run.state === "incomplete") ?? attempt;
  if (!receipt) return { target: resolvedTarget, attempt, receipt: null, data: null, loadError: null };
  try {
    const projection = await api.loadCanonicalProjection<T>(receipt.id);
    if (!projection || typeof projection !== "object") throw new Error("Stored scan evidence is unavailable.");
    if (projection.runId && projection.runId !== receipt.id) throw new Error("Stored scan evidence belongs to a different run.");
    return { target: resolvedTarget, attempt, receipt, data: { ...projection, runId: receipt.id, state: receipt.state }, loadError: null };
  } catch (error) {
    return { target: resolvedTarget, attempt, receipt, data: null, loadError: String(error) };
  }
}
