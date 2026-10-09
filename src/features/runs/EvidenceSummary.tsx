import { useId, useState, type ReactNode } from "react";
import { ChevronDown } from "lucide-react";
import type { BinaryScanResult, CanonicalRun, DependencyScanResult, HistoryScanResult, ImageScanOutcome, ScanRunDetail } from "../../lib/types";

type Receipt = { id?: string | null; state?: string | null; saved?: boolean; observedAt?: string | number | null };
export type Evidence = {
  receipt: Receipt;
  findings: string;
  coverage: string;
  caveats: string[];
  limitations: string[];
  nextAction: string;
};

const count = (value: number, singular: string, plural = `${singular}s`) => `${value.toLocaleString()} ${value === 1 ? singular : plural}`;
const warnings = (...groups: Array<readonly string[] | undefined>) => [...new Set(groups.flatMap(group => group ?? []).filter(Boolean))];
const canonicalReceipt = (run: CanonicalRun | null | undefined, id?: string | null, state?: string): Receipt => ({ id: run?.id ?? id, state: run?.state ?? state, saved: run ? true : id ? true : undefined, observedAt: run?.updatedAtMs });
const canonicalWarnings = (run?: CanonicalRun | null) => run?.warnings.map(warning => typeof warning === "string" ? warning : warning.message) ?? [];

export function sourceEvidence(run: ScanRunDetail): Evidence {
  return {
    receipt: { id: run.runId, state: run.status, saved: run.persistence.status === "saved", observedAt: run.completedAt ?? run.startedAt },
    findings: `${count(run.summary.totalFindings, "finding")} recorded`,
    coverage: `${count(run.summary.filesScanned, "file")} scanned · ${run.summary.filesSkipped.toLocaleString()} skipped`,
    caveats: warnings(run.summary.coverageWarnings, run.maintenanceWarning ? [run.maintenanceWarning] : [], [
      ...(run.status !== "completed" ? ["This receipt is incomplete. Absence of findings is unproven."] : []),
      ...(run.persistence.status === "notSaved" ? ["This receipt is available only in this window until it is saved."] : []),
    ]),
    limitations: ["Source rules cover the files read by this run; absence does not establish that excluded or unreadable files are safe."],
    nextAction: run.persistence.status === "notSaved" ? "Retry saving this receipt before closing oxAudit." : run.status !== "completed" || run.summary.filesSkipped > 0 || run.summary.coverageWarnings?.length ? "Resolve coverage limits and rerun; review any recorded findings." : run.summary.totalFindings > 0 ? "Review recorded findings and their evidence before deciding what to fix." : "Check the recorded scope and scan options before relying on this empty result.",
  };
}

export function dependencyEvidence(result: DependencyScanResult, receipt?: CanonicalRun | null): Evidence {
  const summary = result.summary;
  const complete = summary.advisoryCoverage === "complete";
  return {
    receipt: canonicalReceipt(receipt, summary.runId, "completed"),
    findings: `${count(summary.vulnerabilitiesFound, "advisory", "advisories")} recorded`,
    coverage: `${summary.packagesQueried.toLocaleString()} of ${summary.packagesFound.toLocaleString()} packages queried · ${complete ? "Advisory coverage recorded for queried packages" : "Advisory coverage unknown"} · ${summary.advisorySource || "Advisory source unknown"} · Exploitation enrichment ${summary.enrichment?.status ?? "unknown"}`,
    caveats: warnings(summary.inventoryNotes, summary.advisoryNotes, summary.enrichment?.warnings, canonicalWarnings(receipt), [
      ...(!complete ? ["An empty advisory list does not establish a clean result; this receipt did not record complete advisory coverage."] : []),
    ]),
    limitations: ["Advisory matching covers identified pinned packages; it does not prove runtime reachability or absence of unpublished vulnerabilities.", "Missing exploitation signals do not establish absence of exploitation."],
    nextAction: !complete ? "Rerun with available advisory data to establish recorded package coverage." : summary.vulnerabilitiesFound > 0 ? "Review upgrade groups, affected installations, and advisory evidence." : "Check package scope and the recorded advisory source before relying on this empty result.",
  };
}

export function binaryEvidence(result: BinaryScanResult, receipt?: CanonicalRun | null, notes: string[] = [], offline?: boolean): Evidence {
  const semantic = result.semanticAnalysis;
  return {
    receipt: canonicalReceipt(receipt, undefined, "completed"),
    findings: `${count(result.summary.vulnerabilities, "CVE")} recorded${semantic ? ` · ${count(semantic.findings.length, "semantic candidate")}` : ""}`,
    coverage: `${count(result.summary.components, "component")} identified · ${result.scanners.join(" + ") || "Scanners unknown"} · Advisory coverage unknown${offline === true ? " · Offline database" : ""}`,
    caveats: warnings(canonicalWarnings(receipt), notes, semantic?.limitations, [
      ...(result.summary.vulnerabilities === 0 ? ["Zero CVEs does not establish a safe binary; advisory completeness is unproven."] : []),
      ...(semantic?.unresolvedEdges ? [`${count(semantic.unresolvedEdges, "call edge")} unresolved; deep analysis cannot establish complete call coverage.`] : []),
    ]),
    limitations: ["Scanner recognition and advisory completeness are not recorded."],
    nextAction: notes.length || canonicalWarnings(receipt).length ? "Resolve scanner or advisory limits and rerun; review recorded candidates." : result.summary.vulnerabilities > 0 || semantic?.findings.length ? "Review CVE matches and semantic candidate evidence before deciding what to fix." : "Check scanner recognition and advisory availability before relying on this empty result.",
  };
}

export function imageEvidence(outcome: ImageScanOutcome, receipt?: CanonicalRun | null): Evidence {
  return {
    receipt: canonicalReceipt(receipt, outcome.runId, outcome.state ?? "completed"),
    findings: `${count(outcome.result.summary.vulnerabilities, "vulnerability", "vulnerabilities")} recorded`,
    coverage: `${count(outcome.result.summary.components, "component")} identified · ${count(outcome.layers.length, "layer")} recorded · ${outcome.offline ? "Offline advisories" : "Online advisories permitted"} · Advisory coverage unknown`,
    caveats: warnings(outcome.notes, outcome.localEvidence?.notes, canonicalWarnings(receipt), [
      ...(outcome.result.summary.vulnerabilities === 0 ? ["Zero vulnerabilities does not establish a clean image; advisory completeness is unproven."] : []),
      ...(outcome.state && outcome.state !== "completed" ? [`Coverage is unproven for this ${outcome.state} receipt. Zero recorded vulnerabilities does not establish a clean image.`] : []),
      ...(outcome.localEvidence ? ["Pre-scan identity snapshot. This records evidence before scanning and does not bind the bytes read later by the scan."] : []),
      ...(outcome.localEvidence && !outcome.localEvidence.complete ? ["Local identity capture is incomplete; complete byte identity is unproven."] : []),
      ...(outcome.localEvidence?.file?.changedDuringRead === true ? ["The file changed while its identity was captured."] : []),
    ]),
    limitations: ["Image package recognition and advisory completeness are not recorded.", "Offline absence does not establish a clean result."],
    nextAction: outcome.state && outcome.state !== "completed" || outcome.offline || outcome.notes.length ? "Resolve advisory or identity limits and rerun; review any recorded vulnerabilities." : outcome.result.summary.vulnerabilities > 0 ? "Review the package advisory matches and recorded image identity." : "Check the image identity and advisory scope before relying on this empty result.",
  };
}

export function historyEvidence(result: HistoryScanResult, receipt?: CanonicalRun | null): Evidence {
  const partial = result.truncated || Boolean(result.state && result.state !== "completed");
  const contextUnknown = !result.gitContext || result.gitContext.contextChanged !== false || !result.gitContext.refsCompleteAfter;
  return {
    receipt: canonicalReceipt(receipt, result.runId, result.state),
    findings: `${count(result.findings.length, "finding")} recorded`,
    coverage: `${count(result.blobsScanned, "blob")} scanned · ${result.blobsSkipped.toLocaleString()} skipped · ref-reachable history only`,
    caveats: warnings(canonicalWarnings(receipt), result.limitNote ? [result.limitNote] : [], [
      ...(partial ? ["The findings are partial; absence of historical secrets is unproven."] : []),
      ...(result.blobsSkipped > 0 ? ["Skipped blobs were not covered; absence in those objects is unproven."] : []),
      ...(contextUnknown ? [result.gitContext?.contextChanged === true ? "Git refs changed during the scan; complete current history coverage is unproven." : "Git history coverage changed or is unknown: the final Git ref snapshot is unavailable or unknown."] : []),
    ]),
    limitations: ["Dangling Git objects are not enumerated. No findings is not proof no credential was ever typed.", ...(!result.validation ? ["Live provider validation was not recorded for this run."] : [])],
    nextAction: result.findings.length > 0 ? "Review historical evidence and rotate exposed credentials; deletion does not close a leak." : partial || result.blobsSkipped || contextUnknown ? "Rerun after resolving history coverage limits before relying on this empty result." : "Check the recorded Git scope before relying on this empty result.",
  };
}

export function EvidenceSummary({ label, evidence, running = false, cancelling = false, operation, attempt, operationWarnings, action, children }: {
  label: string; evidence: Evidence; running?: boolean; cancelling?: boolean; operation?: string | null; attempt?: CanonicalRun | null; operationWarnings?: string[]; action?: ReactNode; children?: ReactNode;
}) {
  const [expanded, setExpanded] = useState(false);
  const detailsId = useId();
  const { receipt } = evidence;
  const date = receipt.observedAt == null ? null : new Date(receipt.observedAt);
  const observed = date && Number.isFinite(date.getTime()) ? date.toISOString() : null;
  const differentAttempt = attempt && attempt.id !== receipt.id;
  const attemptWarnings = warnings(differentAttempt ? canonicalWarnings(attempt) : [], operationWarnings);
  const operationLabel = running ? cancelling ? "Cancellation requested" : "Operation running" : operation || (differentAttempt ? `Latest attempt ${attempt.state}` : attempt?.state === "failed" || attempt?.state === "cancelled" ? `Latest saved attempt: ${attempt.state}` : receipt.state === "completed" ? "Operation completed" : receipt.state ? `Receipt ${receipt.state}` : "Operation state unknown");
  return <section aria-label={`${label} evidence summary`} className="rounded-sm border border-border bg-surface-secondary text-[12px]">
    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
      <h2 className="font-semibold text-text-primary">Evidence summary</h2>
      <p role="status" className={running ? "text-accent" : differentAttempt || operation && operation !== "Operation completed" || !operation && receipt.state !== "completed" ? "text-warning" : "text-text-secondary"}>{operationLabel}</p>
    </div>
    <dl className="grid gap-3 px-3 py-3 min-[700px]:grid-cols-[1fr_1fr_2fr]">
      <div><dt className="text-[11px] font-semibold text-text-muted">Displayed receipt</dt><dd className="mt-1 text-text-primary">{receipt.saved === false ? "Not saved" : receipt.saved ? "Saved receipt" : "Save status unknown"} · {receipt.state ?? "state unknown"}</dd><dd className="mt-1 text-[11px] text-text-muted">{observed ? <>Recorded time: <time dateTime={observed}>{observed}</time></> : "Recorded time unknown"}</dd></div>
      <div><dt className="text-[11px] font-semibold text-text-muted">Findings</dt><dd className="mt-1 text-text-primary">{evidence.findings}</dd></div>
      <div><dt className="text-[11px] font-semibold text-text-muted">Recorded coverage</dt><dd className="mt-1 text-text-secondary">{evidence.coverage}</dd></div>
    </dl>
    {running && <p className="px-3 pb-2 text-text-muted">Previous evidence is shown while this operation runs.</p>}
    <div className="border-t border-border px-3 py-2.5">
      {evidence.caveats.length > 0 && <><p className="font-medium text-warning">Recorded limits</p><ul aria-label="Evidence limits" className="mt-1 list-disc space-y-1 pl-4 text-text-secondary">{evidence.caveats.map(caveat => <li key={caveat}>{caveat}</li>)}</ul></>}
      {attemptWarnings.length > 0 && <div aria-label="Latest attempt warnings" className="mt-2"><p className="font-medium text-warning">Latest attempt warnings</p><ul className="mt-1 list-disc space-y-1 pl-4 text-text-secondary">{attemptWarnings.map(warning => <li key={warning}>{warning}</li>)}</ul></div>}
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2"><p className="text-text-primary"><span className="font-semibold">Next: </span>{evidence.nextAction}</p>{action}</div>
      <button type="button" aria-expanded={expanded} aria-controls={detailsId} onClick={() => setExpanded(value => !value)} className="mt-3 inline-flex items-center gap-1 rounded-sm text-text-muted hover:text-text-primary focus-visible:outline-2 focus-visible:outline-accent">
        <ChevronDown size={12} aria-hidden="true" className={expanded ? "rotate-180" : ""} />Evidence details
      </button>
      <div id={detailsId} hidden={!expanded} className="mt-2 space-y-2 border-t border-border pt-2 text-[11px] text-text-muted">
        <p>Run ID: <span className="break-all font-mono">{receipt.id || "Identity unknown"}</span></p>
        {differentAttempt && <p>Latest attempt: {attempt.state} · <span className="break-all font-mono">{attempt.id}</span></p>}
        <p>Completed execution records what ran; it does not establish safety or complete coverage.</p>
        {evidence.limitations.map(limitation => <p key={limitation}>{limitation}</p>)}
        {children}
      </div>
    </div>
  </section>;
}
