import type { Severity } from "../lib/types";
import { severityColor, severityDot } from "../lib/format";

export function SeverityBadge({ severity, showLabel = true }: { severity: Severity | string | null; showLabel?: boolean }) {
  const sev = severity?.trim().toLowerCase() || "unknown";
  return (
    <span
      aria-label={showLabel ? undefined : `${sev} severity`}
      className={`inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${severityColor(sev)}`}
    >
      <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${severityDot(sev)}`} />
      {showLabel && sev}
    </span>
  );
}
