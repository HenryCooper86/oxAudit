import type { Finding, ReviewRequest, ReviewState } from "../../lib/types";

/**
 * Multi-select and bulk-review logic for the finding list.
 *
 * A first scan of a real project produces hundreds of findings, most of them
 * one or two classes. Dismissing them one at a time is where a scanner gets
 * abandoned on day one, so this is the difference between a tool someone
 * evaluates and a tool someone adopts.
 *
 * Kept out of the component because the part that matters is *which* findings a
 * decision lands on. Getting that wrong writes a wrong entry into an
 * append-only audit trail, and no amount of rendering care compensates.
 */

/** Fingerprints are the stable identity; list positions are not. */
export type Selection = ReadonlySet<string>;

export const EMPTY_SELECTION: Selection = new Set<string>();

export function isSelected(selection: Selection, fingerprint: string): boolean {
  return selection.has(fingerprint);
}

export function toggle(selection: Selection, fingerprint: string): Selection {
  const next = new Set(selection);
  if (!next.delete(fingerprint)) next.add(fingerprint);
  return next;
}

/**
 * Select every finding currently visible.
 *
 * Deliberately scoped to what is on screen rather than to the whole run: the
 * filters are how a reviewer expresses "this class", and a Select all that
 * reached past them would act on findings nobody had looked at.
 */
export function selectAll(visible: readonly Finding[]): Selection {
  return new Set(visible.map((finding) => finding.fingerprint));
}

/**
 * Extend a selection from an anchor to a target, over the visible order.
 *
 * This is shift-click. Both ends are included, and direction does not matter.
 */
export function selectRange(
  selection: Selection,
  visible: readonly Finding[],
  anchorFingerprint: string,
  targetFingerprint: string,
): Selection {
  const anchor = visible.findIndex((finding) => finding.fingerprint === anchorFingerprint);
  const target = visible.findIndex((finding) => finding.fingerprint === targetFingerprint);
  if (anchor === -1 || target === -1) return selection;

  const next = new Set(selection);
  const [from, to] = anchor <= target ? [anchor, target] : [target, anchor];
  for (let index = from; index <= to; index += 1) {
    next.add(visible[index].fingerprint);
  }
  return next;
}

/**
 * Drop anything no longer on screen.
 *
 * Called when the filters change. Without it a reviewer could filter to
 * secrets, select forty, filter to something else, and apply a decision to
 * findings they can no longer see.
 */
export function pruneToVisible(selection: Selection, visible: readonly Finding[]): Selection {
  const allowed = new Set(visible.map((finding) => finding.fingerprint));
  const next = new Set<string>();
  for (const fingerprint of selection) {
    if (allowed.has(fingerprint)) next.add(fingerprint);
  }
  return next;
}

export interface BulkDraft {
  state: ReviewState;
  reason: string;
  expiresAt: string;
}

export interface BulkValidation {
  valid: boolean;
  /** Why the decision cannot be recorded, phrased for the person reading it. */
  problems: string[];
}

/** States a bulk action may apply. */
export const BULK_STATES: Array<{ value: ReviewState; label: string }> = [
  { value: "acceptedRisk", label: "Accepted risk" },
  { value: "suppressed", label: "Suppressed" },
  { value: "candidate", label: "Reset to candidate" },
];

/**
 * Whether a bulk decision can be recorded.
 *
 * `confirmed` and `falsePositive` are absent from `BULK_STATES` on purpose.
 * Both are verdicts about a specific finding — confirming a vulnerability, or
 * naming the gate that eliminates it, requires evidence that cannot be true of
 * forty findings at once. Offering them in bulk would turn a considered
 * judgement into a checkbox.
 */
export function validateBulkDraft(selection: Selection, draft: BulkDraft): BulkValidation {
  const problems: string[] = [];

  if (selection.size === 0) {
    problems.push("Select at least one finding.");
  }
  if (draft.state !== "candidate" && !draft.reason.trim()) {
    problems.push("Give a reason. A dismissal with no justification looks reviewed without being reviewed.");
  }
  if (draft.expiresAt.trim()) {
    const timestamp = Date.parse(draft.expiresAt);
    if (!Number.isFinite(timestamp)) {
      problems.push("The expiry is not a valid date.");
    } else if (timestamp <= Date.now()) {
      problems.push("Choose an expiry in the future, or leave it empty.");
    }
  }

  return { valid: problems.length === 0, problems };
}

/**
 * Turn a bulk decision into one request per selected finding.
 *
 * Each finding gets its own record, carrying its own category and fingerprint
 * version. A bulk action is a convenience for the reviewer, not a different
 * kind of decision in the history.
 */
export function buildBulkRequests(
  projectId: string,
  visible: readonly Finding[],
  selection: Selection,
  draft: BulkDraft,
): ReviewRequest[] {
  return visible
    .filter((finding) => selection.has(finding.fingerprint))
    .map((finding) => ({
      projectId,
      fingerprintVersion: finding.fingerprintVersion,
      fingerprint: finding.fingerprint,
      category: finding.category,
      state: draft.state,
      reason: draft.reason.trim(),
      evidence: null,
      entryPoint: null,
      dataFlow: null,
      gates: [],
      decidingGate: null,
      expiresAt: draft.expiresAt.trim() ? draft.expiresAt : null,
      origin: "local",
    }));
}

/**
 * A one-line summary of what a bulk action will do, for the confirm control.
 *
 * Naming the count and the decision is what stops "Apply" being a button
 * somebody presses without knowing its blast radius.
 */
export function describeBulkAction(selection: Selection, draft: BulkDraft): string {
  const count = selection.size;
  const noun = count === 1 ? "finding" : "findings";
  const label =
    BULK_STATES.find((entry) => entry.value === draft.state)?.label ?? draft.state;
  return `${label} · ${count} ${noun}`;
}
