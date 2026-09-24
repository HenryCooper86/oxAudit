import type { JSX } from "react";
import type { ScanRunSummary, SeverityCounts } from "../../lib/types";
import { fmtDateTime } from "../../lib/format";

const LEVELS = [
  { key: "critical", label: "critical", color: "var(--sev-critical)" },
  { key: "high", label: "high", color: "var(--sev-high)" },
  { key: "medium", label: "medium", color: "var(--sev-medium)" },
  { key: "low", label: "low", color: "var(--sev-low)" },
  { key: "info", label: "info", color: "var(--sev-info)" },
] as const;

/** How many runs the chart shows; a longer history keeps its newest tail. */
const MAX_POINTS = 30;
const CHART_WIDTH = 640;
const CHART_HEIGHT = 120;
const PLOT_BOTTOM = 114;
const PLOT_TOP = 6;

function levelCounts(counts: SeverityCounts): Array<{ label: string; value: number }> {
  return LEVELS.map((level) => ({ label: level.label, value: counts[level.key] }));
}

/**
 * Severity mix over stored runs, oldest to newest. Counts, not predictions:
 * the columns say what past scans found, and the honest limits (stored runs
 * for this project only; new/resolved only when a baseline was recorded)
 * are stated rather than smoothed over.
 */
export function SeverityTrend(props: { runs: ScanRunSummary[] }): JSX.Element {
  const { runs } = props;
  // Runs arrive newest-first; the chart reads left-to-right in time.
  const completed = runs
    .filter((run) => run.status === "completed")
    .slice(0, MAX_POINTS)
    .reverse();
  const maxTotal = Math.max(
    1,
    ...completed.map((point) => point.severityCounts.critical + point.severityCounts.high + point.severityCounts.medium + point.severityCounts.low + point.severityCounts.info),
  );

  return (
    <section
      aria-labelledby="severity-trend-title"
      className="overflow-hidden rounded-sm border border-border bg-surface-secondary"
    >
      <div className="border-b border-border px-3 py-2.5">
        <h2 id="severity-trend-title" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">
          Severity trend
        </h2>
      </div>
      {completed.length === 0 ? (
        <p className="px-3 py-4 text-[12px] text-text-muted">
          {runs.length === 0
            ? "No stored runs yet — the trend appears once scans are saved for this project."
            : "No completed runs yet — unfinished scans carry no counts to plot."}
        </p>
      ) : (
        <div className="px-3 py-3">
          <svg
            viewBox={`0 0 ${CHART_WIDTH} ${CHART_HEIGHT}`}
            role="img"
            aria-label={`Findings by severity across the ${completed.length} most recent completed run${completed.length === 1 ? "" : "s"}`}
            className="h-28 w-full"
          >
            {completed.map((run, index) => {
              const slot = CHART_WIDTH / completed.length;
              const columnWidth = Math.min(26, slot * 0.6);
              const x = slot * index + (slot - columnWidth) / 2;
              let y = PLOT_BOTTOM;
              return (
                <g key={run.runId} role="listitem" aria-label={columnLabel(run)}>
                  <title>{columnLabel(run)}</title>
                  {levelCounts(run.severityCounts).map((level) => {
                    if (level.value === 0) return null;
                    const height = (level.value / maxTotal) * (PLOT_BOTTOM - PLOT_TOP);
                    y -= height;
                    return (
                      <rect
                        key={level.label}
                        x={x}
                        y={y}
                        width={columnWidth}
                        height={height}
                        fill={LEVELS.find((entry) => entry.label === level.label)?.color}
                        rx={1}
                      />
                    );
                  })}
                  {run.totalFindings === 0 && (
                    <rect x={x} y={PLOT_BOTTOM - 2} width={columnWidth} height={2} fill="var(--border)" rx={1} />
                  )}
                </g>
              );
            })}
            <line x1={0} y1={PLOT_BOTTOM} x2={CHART_WIDTH} y2={PLOT_BOTTOM} stroke="var(--border)" strokeWidth={1} />
          </svg>
          <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1">
            {levelCounts(completed[completed.length - 1].severityCounts)
              .filter((level) => level.value > 0)
              .map((level) => (
                <span key={level.label} className="inline-flex items-center gap-1.5 text-[11px] text-text-secondary">
                  <span
                    aria-hidden="true"
                    className="h-2 w-2 rounded-full"
                    style={{ backgroundColor: LEVELS.find((entry) => entry.label === level.label)?.color }}
                  />
                  {level.value} {level.label}
                </span>
              ))}
          </div>
          <p className="mt-1.5 text-[11px] text-text-muted">
            Latest run {fmtDateTime(completed[completed.length - 1].completedAt ?? completed[completed.length - 1].startedAt)}:{" "}
            {completed[completed.length - 1].newFindings} new · {completed[completed.length - 1].resolvedFindings} resolved
            against its baseline. Stored runs for this project only; new and resolved need a baseline run.
          </p>
        </div>
      )}
    </section>
  );
}

function columnLabel(run: ScanRunSummary): string {
  const mix = levelCounts(run.severityCounts)
    .filter((level) => level.value > 0)
    .map((level) => `${level.value} ${level.label}`)
    .join(", ");
  return `${fmtDateTime(run.completedAt ?? run.startedAt)}: ${mix || "0 findings"}`;
}
