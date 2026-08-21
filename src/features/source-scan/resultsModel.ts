import type { Finding, FindingScope, ReviewState } from "../../lib/types";
import type { ResultsQuery, ResultView, ViewCounts } from "./types";

const OPEN_SCOPES = new Set<FindingScope>([
  "production",
  "infrastructure",
  "unknown",
]);

export function findingView(finding: Finding): ResultView {
  if (finding.diffStatus === "resolved") return "resolved";

  const state = finding.review?.state ?? "candidate";
  if (state === "confirmed") return "open";
  if (state === "falsePositive" || state === "acceptedRisk" || state === "suppressed") {
    return "closed";
  }

  return OPEN_SCOPES.has(finding.scope ?? "unknown") ? "open" : "otherScopes";
}

export function countViews(findings: readonly Finding[]): ViewCounts {
  const counts: ViewCounts = {
    open: 0,
    otherScopes: 0,
    closed: 0,
    resolved: 0,
  };
  for (const finding of findings) counts[findingView(finding)] += 1;
  return counts;
}

export function filterFindings(
  findings: readonly Finding[],
  query: ResultsQuery,
): Finding[] {
  const search = query.search.trim().toLocaleLowerCase();
  return findings.filter((finding) => {
    if (findingView(finding) !== query.view) return false;
    if (query.category !== "all" && finding.category !== query.category) return false;
    if (query.severity !== "all" && finding.severity !== query.severity) return false;
    if (query.scope !== "all" && (finding.scope ?? "unknown") !== query.scope) return false;
    if (query.language !== "all" && finding.language !== query.language) return false;
    if (!search) return true;

    const haystack = [
      finding.ruleName,
      finding.ruleId,
      finding.filePath,
      finding.title,
      finding.matchText,
    ]
      .join(" ")
      .toLocaleLowerCase();
    return haystack.includes(search);
  });
}

export function nextSelection(
  findings: readonly Finding[],
  selectedFingerprint: string | null,
): string | null {
  if (
    selectedFingerprint &&
    findings.some((finding) => finding.fingerprint === selectedFingerprint)
  ) {
    return selectedFingerprint;
  }
  return findings[0]?.fingerprint ?? null;
}

export interface SanitizedFindingExport {
  category: Finding["category"];
  ruleId: string;
  ruleName: string;
  severity: Finding["severity"];
  title: string;
  description: string;
  filePath: string;
  line: number;
  column: number;
  matchText: string;
  context: string;
  language: string;
  cwe: string | null;
  recommendation: string;
  fingerprintVersion: number;
  fingerprint: string;
  scope: Finding["scope"];
  scopeReason: string | null;
  diffStatus: Finding["diffStatus"];
  reviewState: ReviewState;
}

export function sanitizeExport(
  findings: readonly Finding[],
): SanitizedFindingExport[] {
  return findings.map((finding) => {
    const secret = finding.category === "secret";
    return {
      category: finding.category,
      ruleId: finding.ruleId,
      ruleName: finding.ruleName,
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
      filePath: finding.filePath,
      line: finding.line,
      column: finding.column,
      matchText: secret ? "[REDACTED]" : finding.matchText,
      context: secret ? "[REDACTED]" : finding.context,
      language: finding.language,
      cwe: finding.cwe,
      recommendation: finding.recommendation,
      fingerprintVersion: finding.fingerprintVersion,
      fingerprint: finding.fingerprint,
      scope: finding.scope,
      scopeReason: finding.scopeReason,
      diffStatus: finding.diffStatus,
      reviewState: finding.review?.state ?? "candidate",
    };
  });
}
