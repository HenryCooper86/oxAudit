import { CheckSquare, X } from "lucide-react";
import { useState, type JSX } from "react";

import { Button, Input, Select, Textarea } from "../../components/ui";
import { Field } from "../../components/workbench/Field";
import type { Finding, ReviewRequest, ReviewState } from "../../lib/types";
import {
  BULK_STATES,
  buildBulkRequests,
  describeBulkAction,
  validateBulkDraft,
  type BulkDraft,
  type Selection,
} from "./selectionModel";

/**
 * Records one decision against many findings.
 *
 * Appears only when something is selected, so it costs nothing until a reviewer
 * is actually triaging. The count is on the button rather than buried in the
 * copy: "Apply" without a blast radius is a control people press by accident,
 * and this one writes to an append-only history.
 */
export function BulkReviewBar(props: {
  projectId: string;
  visible: readonly Finding[];
  selection: Selection;
  saving: boolean;
  failures: number;
  onClear(): void;
  onSelectAll(): void;
  onApply(requests: ReviewRequest[]): Promise<void>;
}): JSX.Element | null {
  const { projectId, visible, selection, saving, failures, onClear, onSelectAll, onApply } = props;
  const [draft, setDraft] = useState<BulkDraft>({
    state: "acceptedRisk",
    reason: "",
    expiresAt: "",
  });

  const validation = validateBulkDraft(selection, draft);
  const needsReason = draft.state !== "candidate";

  if (selection.size === 0) return null;

  const apply = () => {
    if (!validation.valid || saving) return;
    void onApply(buildBulkRequests(projectId, visible, selection, draft));
  };

  return (
    <section
      aria-label="Bulk review"
      className="border-t border-border bg-surface-secondary p-4"
    >
      <div className="flex flex-wrap items-center gap-2">
        <CheckSquare size={15} aria-hidden="true" className="text-accent" />
        <h3 className="text-[13px] font-semibold text-text-primary">
          {selection.size} selected
        </h3>
        <button
          type="button"
          onClick={onSelectAll}
          className="text-[11px] text-accent hover:underline"
        >
          Select all {visible.length} filtered findings
        </button>
        <Button
          type="button"
          variant="icon"
          size="sm"
          aria-label="Clear selection"
          onClick={onClear}
          className="ml-auto"
        >
          <X size={14} aria-hidden="true" />
        </Button>
      </div>

      <div className="mt-3 grid gap-3 sm:grid-cols-[minmax(0,12rem)_1fr]">
        <Field label="Decision" htmlFor="bulk-state">
          <Select
            id="bulk-state"
            value={draft.state}
            onChange={(event) =>
              setDraft((current) => ({ ...current, state: event.target.value as ReviewState }))
            }
            disabled={saving}
          >
            {BULK_STATES.map((entry) => (
              <option key={entry.value} value={entry.value}>
                {entry.label}
              </option>
            ))}
          </Select>
        </Field>

        {needsReason && (
          <Field
            label="Reason"
            htmlFor="bulk-reason"
            hint="Recorded against every selected finding, and readable by whoever reviews this next."
          >
            <Textarea
              id="bulk-reason"
              value={draft.reason}
              onChange={(event) =>
                setDraft((current) => ({ ...current, reason: event.target.value }))
              }
              rows={2}
              disabled={saving}
            />
          </Field>
        )}
      </div>

      {needsReason && (
        <div className="mt-3 max-w-sm">
          <Field
            label="Optional expiry"
            htmlFor="bulk-expiry"
            hint="Expired decisions return to the active queue."
          >
            <Input
              id="bulk-expiry"
              type="datetime-local"
              value={draft.expiresAt}
              onChange={(event) =>
                setDraft((current) => ({ ...current, expiresAt: event.target.value }))
              }
              disabled={saving}
            />
          </Field>
        </div>
      )}

      {!validation.valid && (
        <ul className="mt-3 space-y-1">
          {validation.problems.map((problem) => (
            <li key={problem} className="text-[11px] text-error" role="alert">
              {problem}
            </li>
          ))}
        </ul>
      )}

      {failures > 0 && (
        <p className="mt-3 text-[11px] text-warning" role="alert">
          {failures} {failures === 1 ? "finding was" : "findings were"} not recorded. The rest were
          saved — re-run the scan to see the current state before retrying.
        </p>
      )}

      <div className="mt-3 flex items-center gap-2">
        <Button
          type="button"
          variant="primary"
          onClick={apply}
          disabled={!validation.valid || saving}
        >
          {saving ? "Recording…" : describeBulkAction(selection, draft)}
        </Button>
        <span className="text-[11px] text-text-muted">
          Each finding gets its own entry in the review history.
        </span>
      </div>
    </section>
  );
}
