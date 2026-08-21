import type { ComplianceReadinessStatus } from "../../lib/types";

export const READINESS_OPTIONS: Array<{ value: ComplianceReadinessStatus; label: string }> = [
  { value: "supported", label: "Supported by review" },
  { value: "partial", label: "Partially supported" },
  { value: "gap", label: "Gap confirmed" },
  { value: "manualReview", label: "Manual review needed" },
  { value: "notApplicable", label: "Not applicable" },
];

export function readinessLabel(status: ComplianceReadinessStatus): string {
  return READINESS_OPTIONS.find((item) => item.value === status)?.label ?? status;
}

export function readinessClass(status: ComplianceReadinessStatus): string {
  switch (status) {
    case "supported":
      return "border-success-border bg-success-subtle text-success";
    case "partial":
    case "manualReview":
      return "border-warning-border bg-warning-subtle text-warning";
    case "gap":
      return "border-error-border bg-error-subtle text-error";
    case "notApplicable":
      return "border-border bg-surface-active text-text-muted";
  }
}
