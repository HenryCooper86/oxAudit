import type {
  Finding,
  Gate,
  GateNote,
  GateVerdict,
  ReviewOrigin,
  ReviewRequest,
  ReviewState,
} from "../../lib/types";

export const ALL_GATES: readonly Gate[] = [
  "intended",
  "reachable",
  "attackerControlled",
  "sanitized",
  "newCapability",
];

export interface ReviewDraft {
  state: ReviewState;
  reason: string;
  evidence: string;
  entryPoint: string;
  dataFlow: string;
  gates: GateNote[];
  decidingGate: Gate | null;
  expiresAt: string;
  origin: ReviewOrigin;
}

export interface ReviewValidation {
  valid: boolean;
  fieldErrors: Partial<
    Record<
      "reason" | "evidence" | "gates" | "decidingGate" | "expiresAt" | "origin",
      string
    >
  >;
}

export function createReviewDraft(finding: Finding): ReviewDraft {
  const review = finding.review;
  return {
    state: review?.state ?? "candidate",
    reason: review?.reason ?? "",
    evidence: review?.evidence ?? "",
    entryPoint: review?.entryPoint ?? "",
    dataFlow: review?.dataFlow ?? "",
    gates: ALL_GATES.map((gate) => {
      const saved = review?.gates.find((note) => note.gate === gate);
      if (saved) return { ...saved };
      // Nothing recorded by a person yet: start from what the dataflow
      // analysis worked out, so a reviewer edits an argument rather than
      // typing one from scratch. A saved answer always wins — a human
      // decision is never overwritten by a machine suggestion.
      const suggested = finding.analysisGates?.find((note) => note.gate === gate);
      if (suggested) return { ...suggested };
      return { gate, verdict: "unknown", evidence: "" };
    }),
    decidingGate: review?.decidingGate ?? null,
    expiresAt: review?.expiresAt ?? "",
    origin: review?.origin ?? "local",
  };
}

export function updateGate(
  draft: ReviewDraft,
  gate: Gate,
  update: { verdict?: GateVerdict; evidence?: string },
): ReviewDraft {
  return {
    ...draft,
    gates: draft.gates.map((note) =>
      note.gate === gate ? { ...note, ...update } : note,
    ),
  };
}

function futureExpiry(value: string): boolean {
  if (!value.trim()) return true;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && timestamp > Date.now();
}

function activeGateNotes(gates: readonly GateNote[]): GateNote[] {
  return gates.filter(
    (note) => note.verdict !== "unknown" || note.evidence.trim().length > 0,
  );
}

export function validateReviewDraft(
  finding: Finding,
  draft: ReviewDraft,
): ReviewValidation {
  const fieldErrors: ReviewValidation["fieldErrors"] = {};
  if (draft.state === "candidate") return { valid: true, fieldErrors };

  if (!draft.reason.trim()) fieldErrors.reason = "Explain why this decision is appropriate.";
  if (!futureExpiry(draft.expiresAt)) {
    fieldErrors.expiresAt = "Choose a valid expiry in the future.";
  }
  if (draft.origin === "projectPolicy" && draft.state === "confirmed") {
    fieldErrors.origin = "Confirmed reviews must remain local.";
  }

  if (finding.category === "vulnerability" && draft.state === "confirmed") {
    const complete = ALL_GATES.every((gate) => {
      const note = draft.gates.find((candidate) => candidate.gate === gate);
      return note?.verdict === "survives" && Boolean(note.evidence.trim());
    });
    if (!complete) {
      fieldErrors.gates = "Every gate must survive and include supporting evidence.";
    }
    if (draft.decidingGate) {
      fieldErrors.decidingGate = "Confirmed findings do not use an eliminating gate.";
    }
  }

  if (finding.category === "vulnerability" && draft.state === "falsePositive") {
    const notes = activeGateNotes(draft.gates);
    const invalidNote = notes.some(
      (note) => note.verdict === "unknown" || !note.evidence.trim(),
    );
    const eliminating = notes.filter((note) => note.verdict === "eliminates");
    if (invalidNote) fieldErrors.gates = "Every answered gate needs a verdict and evidence.";
    if (
      eliminating.length !== 1 ||
      !draft.decidingGate ||
      eliminating[0]?.gate !== draft.decidingGate
    ) {
      fieldErrors.decidingGate = "Choose the single gate that eliminates this finding.";
    }
  }

  return { valid: Object.keys(fieldErrors).length === 0, fieldErrors };
}

function optional(value: string): string | null {
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function expiry(value: string): string | null {
  if (!value.trim()) return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null;
}

export function buildReviewRequest(
  projectId: string,
  finding: Finding,
  draft: ReviewDraft,
): ReviewRequest {
  const base = {
    projectId,
    fingerprintVersion: finding.fingerprintVersion,
    fingerprint: finding.fingerprint,
    category: finding.category,
    state: draft.state,
    origin: draft.origin,
  } as const;

  if (draft.state === "candidate") {
    return {
      ...base,
      reason: "",
      evidence: null,
      entryPoint: null,
      dataFlow: null,
      gates: [],
      decidingGate: null,
      expiresAt: null,
    };
  }

  const dispositionOnly =
    finding.category === "secret" ||
    draft.state === "acceptedRisk" ||
    draft.state === "suppressed";
  if (dispositionOnly) {
    return {
      ...base,
      reason: draft.reason.trim(),
      evidence: null,
      entryPoint: null,
      dataFlow: null,
      gates: [],
      decidingGate: null,
      expiresAt: expiry(draft.expiresAt),
    };
  }

  const gates =
    draft.state === "confirmed"
      ? draft.gates
      : activeGateNotes(draft.gates);
  return {
    ...base,
    reason: draft.reason.trim(),
    evidence: optional(draft.evidence),
    entryPoint: optional(draft.entryPoint),
    dataFlow: optional(draft.dataFlow),
    gates: gates.map((note) => ({
      gate: note.gate,
      verdict: note.verdict,
      evidence: note.evidence.trim(),
    })),
    decidingGate: draft.state === "falsePositive" ? draft.decidingGate : null,
    expiresAt: expiry(draft.expiresAt),
  };
}
