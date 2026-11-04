import { api } from "../../lib/api";
import { normalizedTarget } from "../../lib/durableRuns";
import type { CanonicalRun, DependencyScanResult, Vulnerability } from "../../lib/types";

export interface SavedDependencySummary {
  runId: string;
  total: number;
  critical: number;
  high: number;
  packages: number;
  coverage: "complete" | "unknown";
}

function isCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

/** Query saved metadata and bounded rows; never load an entire inventory for Home. */
export async function loadDependencyHomeSummary(run: CanonicalRun): Promise<SavedDependencySummary> {
  if (run.kind !== "dependencies" || run.state !== "completed") {
    throw new Error("A completed dependency scan is required.");
  }
  const metadata = await api.loadCanonicalProjectionMetadata<DependencyScanResult>(run.id);
  const summary = metadata?.projection?.summary;
  const total = metadata?.sections?.vulnerabilities;
  if (metadata?.kind !== "pagedProjection" || metadata.projectionKind !== "dependencies" || !summary ||
    typeof summary.path !== "string" || normalizedTarget(summary.path) !== normalizedTarget(run.targetLabel) ||
    (summary.runId != null && summary.runId !== run.id) || !isCount(total) || !isCount(summary.packagesFound)) {
    throw new Error("Saved dependency evidence does not match this completed run.");
  }
  let critical = 0, high = 0;
  if (total > 0) {
    const pages = await Promise.all((["critical", "high"] as const).map(severity =>
      api.loadCanonicalProjectionPage<Vulnerability>(run.id, "vulnerabilities", { severity, offset: 0, limit: 1 }),
    ));
    if (pages.some(page => !page || page.total !== total || !isCount(page.filteredTotal) || page.filteredTotal > total) ||
      pages[0].filteredTotal + pages[1].filteredTotal > total) {
      throw new Error("Saved dependency counts are unavailable. Retry the summary.");
    }
    [critical, high] = pages.map(page => page.filteredTotal);
  }
  return { runId: run.id, total, critical, high, packages: summary.packagesFound,
    coverage: summary.advisoryCoverage === "complete" ? "complete" : "unknown" };
}
