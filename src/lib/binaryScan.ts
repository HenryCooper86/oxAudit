/**
 * Severity ranking for binary-scan results.
 *
 * Kept out of the page component so the "this severity and above" filter — the
 * one piece of logic that can silently hide a finding — is testable.
 */

import type { BinaryComponent } from "./types";

/** Ordered so a filter can express a floor rather than an exact match. */
export const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export const SEVERITY_FILTERS = ["all", "low", "medium", "high", "critical"] as const;
export type SeverityFilter = (typeof SEVERITY_FILTERS)[number];

export function severityRank(severity: string): number {
  return SEVERITY_RANK[severity] ?? 0;
}

/**
 * The worst severity among a component's CVEs, for the summary badge.
 * A component with no CVEs, or only unrecognized ones, reads as "unknown"
 * rather than borrowing the lowest known rank.
 */
export function highestSeverity(component: BinaryComponent): string {
  let worst = "unknown";
  for (const vulnerability of component.vulnerabilities) {
    if (severityRank(vulnerability.severity) > severityRank(worst)) {
      worst = vulnerability.severity;
    }
  }
  return worst;
}

/**
 * Keep components with at least one CVE at or above `filter`.
 *
 * The floor is applied per-CVE, not to the component's worst severity, so a
 * component is shown whenever it has *any* qualifying finding.
 */
export function filterComponents(
  components: readonly BinaryComponent[],
  filter: SeverityFilter,
): BinaryComponent[] {
  if (filter === "all") return [...components];
  const floor = severityRank(filter);
  return components.filter((component) =>
    component.vulnerabilities.some(
      (vulnerability) => severityRank(vulnerability.severity) >= floor,
    ),
  );
}
