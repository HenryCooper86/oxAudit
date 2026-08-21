import { ShieldCheck, X } from "lucide-react";
import { useEffect, useMemo, useState, type FormEvent, type JSX } from "react";
import { Button, Input, Select, Textarea } from "../../components/ui";
import { Field } from "../../components/workbench/Field";
import type { CommandError, Finding, Gate, ReviewRequest, ReviewState } from "../../lib/types";
import {
  ALL_GATES,
  buildReviewRequest,
  createReviewDraft,
  updateGate,
  validateReviewDraft,
} from "./reviewModel";

const STATE_LABELS: Array<{ value: ReviewState; label: string }> = [
  { value: "candidate", label: "Candidate" },
  { value: "confirmed", label: "Confirmed" },
  { value: "falsePositive", label: "False positive" },
  { value: "acceptedRisk", label: "Accepted risk" },
  { value: "suppressed", label: "Suppressed" },
];

const GATE_CONTENT: Record<Gate, { title: string; question: string }> = {
  intended: {
    title: "Intended behavior",
    question: "Is this the application doing what it was designed to do?",
  },
  reachable: {
    title: "Production reachability",
    question: "Is this code reachable in a production build?",
  },
  attackerControlled: {
    title: "Attacker control",
    question: "Is the input genuinely attacker-controlled?",
  },
  sanitized: {
    title: "Effective sanitization",
    question: "Does sanitization cover every path that reaches this sink?",
  },
  newCapability: {
    title: "Security impact",
    question: "Does exploitation give the attacker a new capability?",
  },
};

export function FindingReviewForm(props: {
  projectId: string;
  finding: Finding;
  saving: boolean;
  error: CommandError | null;
  onSubmit(request: ReviewRequest): Promise<void>;
  onCancel(): void;
}): JSX.Element {
  const { projectId, finding, saving, error, onSubmit, onCancel } = props;
  const [draft, setDraft] = useState(() => createReviewDraft(finding));
  const validation = useMemo(() => validateReviewDraft(finding, draft), [draft, finding]);
  const isGateReview =
    finding.category === "vulnerability" &&
    (draft.state === "confirmed" || draft.state === "falsePositive");
  const showExpiry = ["falsePositive", "acceptedRisk", "suppressed"].includes(draft.state);

  useEffect(() => {
    setDraft(createReviewDraft(finding));
  }, [finding.fingerprint, finding.review?.id]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!validation.valid || saving) return;
    void onSubmit(buildReviewRequest(projectId, finding, draft));
  };

  return (
    <form onSubmit={submit} className="border-t border-border bg-surface-primary p-4 sm:p-5" aria-label="Review finding">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck size={15} aria-hidden="true" className="text-accent" />
            <h3 className="text-[13px] font-semibold text-text-primary">Review decision</h3>
          </div>
          <p className="mt-1 text-[11px] leading-relaxed text-text-muted">
            Record a durable, evidence-backed decision. AI suggestions never submit this form.
          </p>
        </div>
        <Button type="button" onClick={onCancel} variant="icon" size="sm" aria-label="Close review form">
          <X size={14} aria-hidden="true" />
        </Button>
      </div>

      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <Field label="Decision" htmlFor="review-state">
          <Select
            id="review-state"
            value={draft.state}
            onChange={(event) =>
              setDraft((current) => ({ ...current, state: event.target.value as ReviewState }))
            }
            disabled={saving || finding.diffStatus === "resolved"}
          >
            {STATE_LABELS.map((state) => (
              <option key={state.value} value={state.value}>{state.label}</option>
            ))}
          </Select>
        </Field>
        {draft.state !== "candidate" && (
          <Field label="Decision origin" htmlFor="review-origin" error={validation.fieldErrors.origin}>
            <Select
              id="review-origin"
              value={draft.origin}
              onChange={(event) => setDraft((current) => ({ ...current, origin: event.target.value as "local" | "projectPolicy" }))}
              disabled={saving}
            >
              <option value="local">Local to this device</option>
              <option value="projectPolicy" disabled={draft.state === "confirmed"}>Project policy</option>
            </Select>
          </Field>
        )}
      </div>

      {draft.state !== "candidate" && (
        <div className="mt-4">
          <Field
            label="Reason"
            htmlFor="review-reason"
            hint="State the evidence or business reason another reviewer needs to understand this decision."
            error={validation.fieldErrors.reason}
          >
            <Textarea
              id="review-reason"
              value={draft.reason}
              onChange={(event) => setDraft((current) => ({ ...current, reason: event.target.value }))}
              rows={3}
              disabled={saving}
              aria-describedby={validation.fieldErrors.reason ? "review-reason-error" : "review-reason-hint"}
            />
          </Field>
        </div>
      )}

      {isGateReview && (
        <div className="mt-5 space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Entry point" htmlFor="review-entry-point" hint="Where untrusted input first enters the application.">
              <Input id="review-entry-point" value={draft.entryPoint} onChange={(event) => setDraft((current) => ({ ...current, entryPoint: event.target.value }))} disabled={saving} />
            </Field>
            <Field label="Data flow" htmlFor="review-data-flow" hint="Summarize the source-to-sink path.">
              <Input id="review-data-flow" value={draft.dataFlow} onChange={(event) => setDraft((current) => ({ ...current, dataFlow: event.target.value }))} disabled={saving} />
            </Field>
          </div>
          <Field label="Overall evidence" htmlFor="review-evidence" error={validation.fieldErrors.evidence}>
            <Textarea id="review-evidence" value={draft.evidence} onChange={(event) => setDraft((current) => ({ ...current, evidence: event.target.value }))} rows={3} disabled={saving} />
          </Field>

          <div>
            <h4 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">Falsification gates</h4>
            <p className="mt-1 text-[11px] text-text-muted">Try to eliminate the candidate before confirming it.</p>
          </div>
          {ALL_GATES.map((gate, index) => {
            const note = draft.gates.find((candidate) => candidate.gate === gate)!;
            const content = GATE_CONTENT[gate];
            return (
              <fieldset key={gate} className="rounded-sm border border-border bg-surface-secondary p-3">
                <legend className="px-1 text-[12px] font-medium text-text-primary">{index + 1}. {content.title}</legend>
                <p className="mt-1 text-[11px] text-text-secondary">{content.question}</p>
                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-2">
                  {(["survives", "eliminates", "unknown"] as const).map((verdict) => (
                    <label key={verdict} className="inline-flex items-center gap-1.5 text-[11px] text-text-secondary">
                      <input
                        type="radio"
                        name={`gate-${gate}`}
                        value={verdict}
                        checked={note.verdict === verdict}
                        onChange={() => setDraft((current) => updateGate(current, gate, { verdict }))}
                        disabled={saving}
                        className="accent-accent"
                      />
                      {verdict === "survives" ? "Survives" : verdict === "eliminates" ? "Eliminates" : "Unknown"}
                    </label>
                  ))}
                </div>
                <Textarea
                  aria-label={`${content.title} evidence`}
                  value={note.evidence}
                  onChange={(event) => setDraft((current) => updateGate(current, gate, { evidence: event.target.value }))}
                  placeholder="Evidence, ideally with a file and line…"
                  rows={2}
                  disabled={saving}
                  className="mt-2"
                />
              </fieldset>
            );
          })}
          {draft.state === "falsePositive" && (
            <Field label="Deciding gate" htmlFor="review-deciding-gate" error={validation.fieldErrors.decidingGate}>
              <Select id="review-deciding-gate" value={draft.decidingGate ?? ""} onChange={(event) => setDraft((current) => ({ ...current, decidingGate: (event.target.value || null) as Gate | null }))} disabled={saving}>
                <option value="">Choose the eliminating gate…</option>
                {ALL_GATES.map((gate) => <option key={gate} value={gate}>{GATE_CONTENT[gate].title}</option>)}
              </Select>
            </Field>
          )}
          {validation.fieldErrors.gates && <p role="alert" className="text-[11px] text-error">{validation.fieldErrors.gates}</p>}
        </div>
      )}

      {showExpiry && (
        <div className="mt-4 max-w-sm">
          <Field label="Optional expiry" htmlFor="review-expiry" hint="Expired decisions return to the active queue." error={validation.fieldErrors.expiresAt}>
            <Input id="review-expiry" type="datetime-local" value={draft.expiresAt.includes("T") ? draft.expiresAt.slice(0, 16) : draft.expiresAt} onChange={(event) => setDraft((current) => ({ ...current, expiresAt: event.target.value }))} disabled={saving} />
          </Field>
        </div>
      )}

      {finding.category === "secret" && draft.state !== "candidate" && (
        <p className="mt-4 border border-warning-border bg-warning-subtle px-3 py-2 text-[11px] leading-relaxed text-text-secondary">
          Secret values are never revealed, validated, or included in this review request.
        </p>
      )}

      {error && (
        <div role="alert" className="mt-4 border border-error-border bg-error-subtle px-3 py-2 text-[11px] text-error">
          <p className="font-medium">{error.message}</p>
          {error.detail && <p className="mt-1 text-text-secondary">{error.detail}</p>}
        </div>
      )}

      <div className="mt-5 flex flex-wrap items-center justify-end gap-2">
        <Button type="button" onClick={onCancel} variant="outline" size="md" disabled={saving}>Cancel</Button>
        <Button type="submit" variant="primary" size="md" disabled={saving || !validation.valid || finding.diffStatus === "resolved"}>
          {saving ? "Saving…" : "Save review"}
        </Button>
      </div>
    </form>
  );
}
