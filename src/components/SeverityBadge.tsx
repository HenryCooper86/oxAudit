import type { Severity } from "../lib/types";
import { severityColor, severityDot } from "../lib/format";

/** oxFuzz's tinted badge: severity tint on a 4px pill, no outline, plus a dot. */
export function SeverityBadge({ severity, showLabel = true }: { severity: Severity | string | null; showLabel?: boolean }) {
  const sev = severity?.trim().toLowerCase() || "unknown";
  return (
    <span
      aria-label={showLabel ? undefined : `${sev} severity`}
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-sm px-1.5 py-0.5 text-[11px] font-semibold uppercase leading-[1.4] tracking-[0.03em] ${severityColor(sev)}`}
    >
      <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${severityDot(sev)}`} />
      {showLabel && sev}
    </span>
  );
}
