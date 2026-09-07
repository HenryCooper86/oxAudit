import type { Finding, ScanRunDetail } from "../../lib/types";
export interface RecheckAssessment { status: "present" | "absent" | "changed" | "notEvaluated"; message: string }
export function assessRecheck(original: ScanRunDetail, finding: Finding, current: ScanRunDetail, comparison: Finding[]): RecheckAssessment {
  if ([original, current].some(run => run.status !== "completed" || run.persistence.status !== "saved") || current.projectId !== original.projectId || current.runId === original.runId || current.policy.status === "invalid") {
    throw new Error("A saved completed recheck from the original project with valid policy is required.");
  }
  const sameIdentity = (entry: Finding) => entry.fingerprint === finding.fingerprint && entry.fingerprintVersion === finding.fingerprintVersion && entry.category === finding.category;
  if (!original.findings.some(entry => sameIdentity(entry) && entry.observationRunId === original.runId)) {
    throw new Error("The selected finding was not observed in the original run.");
  }
  const observed = comparison.find(entry => sameIdentity(entry) && entry.observationRunId === current.runId);
  if (observed) return { status: "present", message: "Still detected: the same finding identity was observed in the new run." };
  const previous = comparison.find(entry => sameIdentity(entry) && entry.observationRunId === original.runId);
  if (previous?.diffStatus !== "resolved" || previous.resolvedByRunId !== current.runId) {
    return { status: "notEvaluated", message: "Not evaluated: the comparison has no matching file and rule-family coverage. Deleted, skipped or unsupported files cannot establish absence." };
  }
  const nearby = comparison.some(entry => entry.observationRunId === current.runId && entry.ruleId === finding.ruleId && entry.category === finding.category && entry.filePath === finding.filePath && Math.abs(entry.line - finding.line) <= 20);
  if (nearby) return { status: "changed", message: "Original identity no longer detected, but the same rule remains within 20 lines in this file. Changed context can change fingerprints; this is not a verified fix." };
  return { status: "absent", message: "No longer detected in the covered file and rule family. This measures pattern absence against the original run; it does not verify exploitability or broad safety." };
}
