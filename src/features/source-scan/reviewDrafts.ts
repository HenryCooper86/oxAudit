import { create } from "zustand";
import type { Finding, ReviewRequest } from "../../lib/types";
import { createReviewDraft, type ReviewDraft } from "./reviewModel";

interface SessionReviewDraft {
  reviewId: string | null;
  draft: ReviewDraft;
  submissions?: Array<{ request: ReviewRequest; draft: ReviewDraft }>;
}

/** Only an acknowledgement of this exact submitted decision can rebase newer edits. */
export function resolveSessionReviewDraft(entry: SessionReviewDraft | undefined, finding: Finding): SessionReviewDraft | undefined {
  if (!entry || entry.reviewId === (finding.review?.id ?? null)) return entry;
  const saved = finding.review;
  if (!saved) return undefined;
  const keys = ["projectId", "fingerprintVersion", "fingerprint", "state", "reason", "origin", "expiresAt", "entryPoint", "dataFlow", "evidence", "decidingGate"] as const;
  const gates = (value: typeof saved.gates) => [...value].sort((a, b) => a.gate.localeCompare(b.gate));
  const submitted = entry.submissions?.find(submission =>
    keys.every(key => saved[key] === submission.request[key]) &&
    JSON.stringify(gates(saved.gates)) === JSON.stringify(gates(submission.request.gates)));
  if (!submitted) return undefined;
  // Retain acknowledgement metadata across remounts, including unchanged saves.
  // Another in-flight acknowledgement must not invalidate subsequent edits.
  return { ...entry, reviewId: saved.id,
    draft: entry.draft === submitted.draft ? createReviewDraft(finding) : entry.draft };
}

export function hasUnsavedReviewDraft(entry: SessionReviewDraft | undefined, finding: Finding): boolean {
  const current = resolveSessionReviewDraft(entry, finding);
  return Boolean(current && JSON.stringify(current.draft) !== JSON.stringify(createReviewDraft(finding)));
}

export function reviewDraftKey(projectId: string, finding: Finding): string {
  return JSON.stringify([projectId, finding.fingerprintVersion, finding.fingerprint]);
}

/** Unsaved work stays in memory; it is never a persisted review decision. */
export const useReviewDraftStore = create<{
  drafts: Record<string, SessionReviewDraft>;
  put(key: string, finding: Finding, draft: ReviewDraft): void;
  submit(key: string, finding: Finding, request: ReviewRequest, draft: ReviewDraft): void;
  reconcile(key: string, expected: SessionReviewDraft, next: SessionReviewDraft | undefined): void;
  discard(key: string, expected?: SessionReviewDraft): void;
}>((set) => ({
  drafts: {},
  put: (key, finding, draft) => set((state) => {
    const drafts = { ...state.drafts };
    const submissions = resolveSessionReviewDraft(state.drafts[key], finding)?.submissions;
    if (!submissions?.length && JSON.stringify(draft) === JSON.stringify(createReviewDraft(finding))) delete drafts[key];
    else drafts[key] = { reviewId: finding.review?.id ?? null, draft,
      submissions };
    return { drafts };
  }),
  submit: (key, finding, request, draft) => set((state) => {
    const entry = resolveSessionReviewDraft(state.drafts[key], finding);
    return { drafts: { ...state.drafts, [key]: {
      reviewId: finding.review?.id ?? null, draft,
      submissions: [...(entry?.submissions ?? []), { request, draft }],
    } } };
  }),
  reconcile: (key, expected, next) => set((state) => {
    if (state.drafts[key] !== expected) return state;
    const drafts = { ...state.drafts };
    if (next) drafts[key] = next;
    else delete drafts[key];
    return { drafts };
  }),
  discard: (key, expected) => set((state) => {
    if (!state.drafts[key] || (expected && state.drafts[key] !== expected)) return state;
    const drafts = { ...state.drafts };
    delete drafts[key];
    return { drafts };
  }),
}));
