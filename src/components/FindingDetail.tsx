import { Bot, Clipboard, ExternalLink, History, ShieldCheck } from "lucide-react";
import { useEffect, useState, type JSX } from "react";
import { diffLabel, reviewLabel, scopeLabel } from "../features/source-scan/FindingList";
import { FindingReviewForm } from "../features/source-scan/FindingReviewForm";
import { fmtDateTime } from "../lib/format";
import { useAppStore } from "../lib/stores";
import type { CommandError, Finding, ReviewRequest } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";
import { Button } from "./ui";

export function FindingDetail({
  projectId,
  finding,
  savingReview,
  reviewError,
  onSaveReview,
  onCopy,
  onOpenFile,
}: {
  projectId: string;
  finding: Finding;
  savingReview: boolean;
  reviewError: CommandError | null;
  onSaveReview: (request: ReviewRequest) => Promise<void>;
  onCopy: (finding: Finding) => void;
  onOpenFile: (finding: Finding) => void;
}): JSX.Element {
  const activeProject = useAppStore((state) => state.activeProject);
  const openAssistant = useAppStore((state) => state.openAssistant);
  const [reviewing, setReviewing] = useState(false);
  const secret = finding.category === "secret";
  const safeMatch = secret && !finding.matchText.includes("[REDACTED]")
    ? "[REDACTED]"
    : finding.matchText;

  useEffect(() => setReviewing(false), [finding.fingerprint, finding.review?.id]);

  const discussFinding = () => {
    const content = [
      `Finding: ${finding.ruleName}`,
      `Severity: ${finding.severity}`,
      `Category: ${finding.category}`,
      `Location: ${finding.filePath}:${finding.line}:${finding.column}`,
      `Scope: ${scopeLabel(finding)}`,
      `Description:\n${finding.description}`,
      secret ? null : `Evidence:\n${finding.matchText}${finding.context ? `\n\n${finding.context}` : ""}`,
      `Recommendation:\n${finding.recommendation}`,
    ]
      .filter((value): value is string => Boolean(value))
      .join("\n\n");

    openAssistant({
      id: crypto.randomUUID(),
      label: `Finding: ${finding.ruleName}`,
      content,
      projectPath: activeProject,
    });
  };

  return (
    <article>
      <div className="p-4 sm:p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <MetadataChip>{secret ? "Secret" : "Vulnerability"}</MetadataChip>
              <MetadataChip>{reviewLabel(finding)}</MetadataChip>
              <MetadataChip>{scopeLabel(finding)}</MetadataChip>
              <MetadataChip>{diffLabel(finding)}</MetadataChip>
              {finding.cwe && (
                <span
                  title={finding.cweExploited ? `${finding.cweExploitedCount} actively exploited CVEs share this weakness class` : finding.cwe}
                  className={`rounded-sm border px-1.5 py-0.5 font-mono text-[11px] ${finding.cweExploited ? "border-sev-critical-border bg-sev-critical-subtle text-sev-critical" : "border-border bg-surface-tertiary text-text-secondary"}`}
                >
                  {finding.cwe}
                </span>
              )}
            </div>
            <h2 className="mt-2 text-[16px] font-semibold leading-snug text-text-primary">{finding.ruleName}</h2>
            <p className="selectable mt-1 break-all font-mono text-[11px] text-text-muted">{finding.filePath}:{finding.line}:{finding.column}</p>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <Button type="button" onClick={() => setReviewing(true)} variant="accent" size="md" disabled={finding.diffStatus === "resolved"}>
              <ShieldCheck size={13} aria-hidden="true" />
              {finding.diffStatus === "resolved" ? "Resolved projection" : "Review finding"}
            </Button>
            <Button type="button" onClick={discussFinding} variant="accent" size="md">
              <Bot size={13} aria-hidden="true" />
              Discuss in Assistant
            </Button>
            <Button type="button" onClick={() => onCopy(finding)} variant="outline" size="md">
              <Clipboard size={13} aria-hidden="true" />
              Copy finding
            </Button>
            <Button type="button" onClick={() => onOpenFile(finding)} variant="primary" size="md">
              <ExternalLink size={13} aria-hidden="true" />
              Open file
            </Button>
          </div>
        </div>

        <section aria-label="Finding run context" className="mt-5 grid gap-2 border-t border-border pt-4 sm:grid-cols-2 xl:grid-cols-4">
          <DetailMetric label="Observed in run" value={finding.observationRunId || "Current run"} mono />
          <DetailMetric label="Resolution boundary" value={finding.resolvedByRunId ?? "—"} mono />
          <DetailMetric label="Scope reason" value={finding.scopeReason ?? "No classifier reason supplied"} />
          <DetailMetric label="Fingerprint" value={finding.fingerprint || "Unavailable"} mono />
        </section>

        <section aria-labelledby="finding-description" className="mt-5">
          <h3 id="finding-description" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">Description</h3>
          <p className="selectable mt-1.5 text-[13px] leading-relaxed text-text-secondary">{finding.description}</p>
        </section>

        <section aria-labelledby="finding-evidence" className="mt-5">
          <h3 id="finding-evidence" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">Evidence</h3>
          <div className="selectable mt-2 overflow-x-auto rounded-sm border border-border bg-surface-primary p-3">
            <p className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-text-muted">{secret ? "Redacted preview" : "Match"}</p>
            <pre className="whitespace-pre-wrap break-all font-mono text-[13px] leading-relaxed text-warning">{safeMatch}</pre>
          </div>
          {!secret && finding.context && (
            <div className="selectable mt-2 overflow-x-auto rounded-sm border border-border bg-surface-primary p-3">
              <p className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-text-muted">Context</p>
              <pre className="whitespace-pre-wrap font-mono text-[13px] leading-relaxed text-text-secondary">{finding.context}</pre>
            </div>
          )}
          {secret && (
            <p className="mt-2 text-[11px] leading-relaxed text-text-muted">Raw detected secret material is intentionally unavailable in the UI, copy actions, exports, and Assistant handoffs.</p>
          )}
        </section>

        <section aria-labelledby="finding-recommendation" className="mt-5 rounded-sm border border-success-border bg-success-subtle p-3">
          <h3 id="finding-recommendation" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-success">Recommendation</h3>
          <p className="selectable mt-1.5 text-[13px] leading-relaxed text-text-secondary">{finding.recommendation}</p>
        </section>

        {finding.review && (
          <section aria-labelledby="finding-review-summary" className="mt-5 rounded-sm border border-border bg-surface-primary p-3">
            <div className="flex items-center gap-2">
              <History size={14} aria-hidden="true" className="text-text-muted" />
              <h3 id="finding-review-summary" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">Current review</h3>
            </div>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <DetailMetric label="Decision" value={reviewLabel(finding)} />
              <DetailMetric label="Origin" value={finding.review.origin === "projectPolicy" ? "Project policy" : "Local"} />
              <DetailMetric label="Updated" value={fmtDateTime(finding.review.updatedAt)} />
              <DetailMetric label="Expires" value={fmtDateTime(finding.review.expiresAt)} />
            </div>
            <p className="mt-3 text-[12px] leading-relaxed text-text-secondary">{finding.review.reason}</p>
            {(finding.review.entryPoint || finding.review.dataFlow) && (
              <div className="mt-3 grid gap-3 border-t border-border pt-3 sm:grid-cols-2">
                <DetailMetric label="Entry point" value={finding.review.entryPoint ?? "—"} />
                <DetailMetric label="Data flow" value={finding.review.dataFlow ?? "—"} />
              </div>
            )}
          </section>
        )}

        {finding.reviewHistory.length > 0 && (
          <details className="mt-3 rounded-sm border border-border bg-surface-primary p-3">
            <summary className="cursor-pointer text-[12px] font-medium text-text-secondary hover:text-text-primary">Review history ({finding.reviewHistory.length})</summary>
            <ol className="mt-3 space-y-3 border-l border-border pl-4">
              {finding.reviewHistory.map((review) => (
                <li key={review.id} className="text-[11px] text-text-secondary">
                  <p className="font-medium text-text-primary">{review.state} · {review.origin === "projectPolicy" ? "Project policy" : "Local"}</p>
                  <p className="mt-0.5 text-text-muted">{fmtDateTime(review.updatedAt)}{review.supersededAt ? ` · superseded ${fmtDateTime(review.supersededAt)}` : ""}</p>
                  <p className="mt-1 leading-relaxed">{review.reason}</p>
                </li>
              ))}
            </ol>
          </details>
        )}
      </div>

      {reviewing && (
        <FindingReviewForm
          projectId={projectId}
          finding={finding}
          saving={savingReview}
          error={reviewError}
          onSubmit={onSaveReview}
          onCancel={() => setReviewing(false)}
        />
      )}
    </article>
  );
}

function MetadataChip({ children }: { children: string }): JSX.Element {
  return <span className="rounded-sm border border-border bg-surface-tertiary px-1.5 py-0.5 text-[10px] font-medium text-text-secondary">{children}</span>;
}

function DetailMetric({ label, value, mono = false }: { label: string; value: string; mono?: boolean }): JSX.Element {
  return (
    <div className="min-w-0">
      <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-text-muted">{label}</p>
      <p className={`mt-1 break-words text-[11px] text-text-secondary ${mono ? "font-mono" : ""}`} title={value}>{value}</p>
    </div>
  );
}
