import { FileCode2, KeyRound } from "lucide-react";
import { useEffect, useRef, type JSX, type KeyboardEvent } from "react";
import { SeverityBadge } from "../../components/SeverityBadge";
import { ResultPagination } from "../../components/workbench/ResultPagination";
import type { Pagination } from "../../lib/pagination";
import { usePagination } from "../../lib/pagination";
import type { DiffStatus, Finding, FindingScope, ReviewState } from "../../lib/types";
import { isSelected, type Selection } from "./selectionModel";

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

/**
 * The finding list, navigable by keyboard and selectable in bulk.
 *
 * Triage is the work: an analyst goes through hundreds of findings, and every
 * trip to the mouse is friction repeated hundreds of times. `j`/`k` and the
 * arrow keys move, `x` selects, `shift` extends — the same vocabulary as a mail
 * client, because that is the closest thing most people have to a triage habit.
 */
export function FindingList(props: {
  findings: Finding[];
  serverPagination?: Pagination & { setPage(page: number): void };
  selectedFingerprint: string | null;
  onSelect(fingerprint: string): void;
  /** Omitted when the caller does not support bulk actions. */
  selection?: Selection;
  onToggleSelect?(fingerprint: string, extend: boolean): void;
}): JSX.Element {
  const { findings, selectedFingerprint, onSelect, selection, onToggleSelect } = props;
  const listRef = useRef<HTMLDivElement>(null);
  const bulkEnabled = Boolean(selection && onToggleSelect);
  const activeIndex = findings.findIndex(finding => finding.fingerprint === selectedFingerprint);
  const localPagination = usePagination(findings, 50, activeIndex);
  const pagination = props.serverPagination ? { ...props.serverPagination, items: findings } : localPagination;

  // Keep the focused row visible when the keyboard moves past the viewport.
  useEffect(() => {
    listRef.current
      ?.querySelector('[data-active="true"]')
      ?.scrollIntoView({ block: "nearest" });
  }, [selectedFingerprint, pagination.page]);

  const move = (delta: number) => {
    if (findings.length === 0) return;
    const current = findings.findIndex((finding) => finding.fingerprint === selectedFingerprint);
    // No selection yet: `j` starts at the top and `k` at the bottom, rather
    // than doing nothing.
    const next =
      current === -1
        ? delta > 0
          ? 0
          : findings.length - 1
        : Math.min(Math.max(current + delta, 0), findings.length - 1);
    onSelect(findings[next].fingerprint);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    // Never swallow a shortcut the window owns, or a modifier combination the
    // platform expects to handle.
    if (event.metaKey || event.ctrlKey || event.altKey) return;

    switch (event.key) {
      case "j":
      case "ArrowDown":
        event.preventDefault();
        move(1);
        return;
      case "k":
      case "ArrowUp":
        event.preventDefault();
        move(-1);
        return;
      case "x":
      case "X":
        if (bulkEnabled && selectedFingerprint && activeIndex >= 0) {
          event.preventDefault();
          onToggleSelect?.(selectedFingerprint, event.shiftKey);
        }
        return;
      case "Home":
        if (findings.length > 0) {
          event.preventDefault();
          onSelect(findings[0].fingerprint);
        }
        return;
      case "End":
        if (findings.length > 0) {
          event.preventDefault();
          onSelect(findings[findings.length - 1].fingerprint);
        }
        return;
      case "PageDown":
      case "PageUp":
        event.preventDefault();
        move(event.key === "PageDown" ? pagination.pageSize : -pagination.pageSize);
        return;
      default:
    }
  };

  return (
    <>
      <div
        ref={listRef}
        role="listbox"
        aria-label="Findings"
        aria-activedescendant={activeIndex >= 0 && (Boolean(props.serverPagination) || (activeIndex >= pagination.start && activeIndex < pagination.end)) ? `finding-${selectedFingerprint}` : undefined}
        aria-multiselectable={bulkEnabled || undefined}
        tabIndex={0}
        onKeyDown={onKeyDown}
        className="max-h-[42rem] divide-y divide-border overflow-y-auto outline-none focus-visible:ring-1 focus-visible:ring-border-focus"
      >
        {pagination.items.map((finding, index) => {
          const Icon = finding.category === "secret" ? KeyRound : FileCode2;
          const active = selectedFingerprint === finding.fingerprint;
          const checked = selection ? isSelected(selection, finding.fingerprint) : false;
          return (
            <div
              key={finding.fingerprint}
              id={`finding-${finding.fingerprint}`}
              role="option"
              aria-posinset={pagination.start + index + 1}
              aria-setsize={pagination.total}
              aria-selected={active}
              data-active={active}
              className={`flex w-full items-start gap-2 border-l-2 px-3 py-3 text-left transition-colors ${
                active ? "border-accent bg-accent-subtle" : "border-transparent hover:bg-surface-hover"
              }`}
            >
              {bulkEnabled && (
                <input
                  type="checkbox"
                  checked={checked}
                  aria-label={`Select ${finding.ruleName} in ${finding.filePath}`}
                  onChange={(event) =>
                    onToggleSelect?.(
                      finding.fingerprint,
                      (event.nativeEvent as MouseEvent | undefined)?.shiftKey ?? false,
                    )
                  }
                  onClick={(event) => event.stopPropagation()}
                  className="mt-1 shrink-0 accent-accent"
                />
              )}
              <button
                type="button"
                onClick={() => onSelect(finding.fingerprint)}
                // The row is reachable through the listbox; taking it out of the
                // tab order stops Tab walking every finding one at a time.
                tabIndex={-1}
                className="flex min-w-0 flex-1 items-start gap-3 text-left"
              >
                <Icon size={15} aria-hidden="true" className="mt-0.5 shrink-0 text-text-muted" />
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-1.5">
                    <span className="min-w-0 flex-1 truncate text-[12px] font-medium text-text-primary">
                      {finding.ruleName}
                    </span>
                    <SeverityBadge severity={finding.severity} />
                  </span>
                  <span className="mt-1 block truncate font-mono text-[11px] text-text-muted">
                    {finding.filePath}:{finding.line}
                  </span>
                  <span className="mt-1.5 flex flex-wrap gap-1.5 text-[10px] text-text-secondary">
                    <span className="rounded-sm border border-border bg-surface-primary px-1.5 py-0.5">
                      {reviewLabel(finding)}
                    </span>
                    <span className="rounded-sm border border-border bg-surface-primary px-1.5 py-0.5">
                      {scopeLabel(finding)}
                    </span>
                    <span className="rounded-sm border border-border bg-surface-primary px-1.5 py-0.5">
                      {diffLabel(finding)}
                    </span>
                  </span>
                  <span className="mt-1.5 block truncate text-[11px] text-text-muted">
                    {safePreview(finding)}
                  </span>
                </span>
              </button>
            </div>
          );
        })}
      </div>
    <ResultPagination pagination={pagination} label="findings" onPageChange={page => {
      pagination.setPage(page);
      const first = props.serverPagination ? undefined : findings[page * pagination.pageSize];
      if (first) onSelect(first.fingerprint);
    }} />
    </>
  );
}
