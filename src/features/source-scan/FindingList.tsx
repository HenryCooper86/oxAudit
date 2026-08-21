import { FileCode2, KeyRound } from "lucide-react";
import type { JSX } from "react";
import { SeverityBadge } from "../../components/SeverityBadge";
import type { DiffStatus, Finding, FindingScope, ReviewState } from "../../lib/types";

const REVIEW_LABELS: Record<ReviewState, string> = {
  candidate: "Candidate",
  confirmed: "Confirmed",
  falsePositive: "False positive",
  acceptedRisk: "Accepted risk",
  suppressed: "Suppressed",
};

const DIFF_LABELS: Record<DiffStatus, string> = {
  new: "New",
  unchanged: "Unchanged",
  resolved: "Resolved",
  notEvaluated: "Not evaluated",
};

const SCOPE_LABELS: Record<FindingScope, string> = {
  production: "Production",
  infrastructure: "Infrastructure",
  test: "Test",
  fixture: "Fixture",
  generated: "Generated",
  vendored: "Vendored",
  documentation: "Documentation",
  unknown: "Unknown scope",
};

export function reviewLabel(finding: Finding): string {
  return REVIEW_LABELS[finding.review?.state ?? "candidate"];
}

export function scopeLabel(finding: Finding): string {
  return SCOPE_LABELS[finding.scope ?? "unknown"];
}

export function diffLabel(finding: Finding): string {
  return DIFF_LABELS[finding.diffStatus ?? "notEvaluated"];
}

function safePreview(finding: Finding): string {
  if (finding.category !== "secret") return finding.matchText;
  return finding.matchText.includes("[REDACTED]") ? finding.matchText : "[REDACTED]";
}

export function FindingList(props: {
  findings: Finding[];
  selectedFingerprint: string | null;
  onSelect(fingerprint: string): void;
}): JSX.Element {
  const { findings, selectedFingerprint, onSelect } = props;
  return (
    <div role="listbox" aria-label="Findings" className="max-h-[42rem] overflow-y-auto divide-y divide-border">
      {findings.map((finding) => {
        const Icon = finding.category === "secret" ? KeyRound : FileCode2;
        const selected = selectedFingerprint === finding.fingerprint;
        return (
          <button
            key={finding.fingerprint}
            type="button"
            role="option"
            aria-selected={selected}
            onClick={() => onSelect(finding.fingerprint)}
            className={`flex w-full items-start gap-3 border-l-2 px-3 py-3 text-left transition-colors ${selected ? "border-accent bg-accent-subtle" : "border-transparent hover:bg-surface-hover"}`}
          >
            <Icon size={15} aria-hidden="true" className="mt-0.5 shrink-0 text-text-muted" />
            <span className="min-w-0 flex-1">
              <span className="flex flex-wrap items-center gap-1.5">
                <span className="min-w-0 flex-1 truncate text-[12px] font-medium text-text-primary">{finding.ruleName}</span>
                <SeverityBadge severity={finding.severity} />
              </span>
              <span className="mt-1 block truncate font-mono text-[11px] text-text-muted">{finding.filePath}:{finding.line}</span>
              <span className="mt-1.5 flex flex-wrap gap-1.5 text-[10px] text-text-secondary">
                <span className="rounded-sm border border-border bg-surface-primary px-1.5 py-0.5">{reviewLabel(finding)}</span>
                <span className="rounded-sm border border-border bg-surface-primary px-1.5 py-0.5">{scopeLabel(finding)}</span>
                <span className="rounded-sm border border-border bg-surface-primary px-1.5 py-0.5">{diffLabel(finding)}</span>
              </span>
              <span className="mt-1.5 block truncate text-[11px] text-text-muted">{safePreview(finding)}</span>
            </span>
          </button>
        );
      })}
    </div>
  );
}
