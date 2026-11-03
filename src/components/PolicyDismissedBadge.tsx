import type { AdvisoryReview } from "../lib/types";

const STATE_LABELS: Record<AdvisoryReview["state"], string> = {
  falsePositive: "False positive",
  acceptedRisk: "Accepted risk",
  suppressed: "Suppressed",
};

/** Marks an advisory the committed advisory policy dismissed: still listed, never gating. */
export function PolicyDismissedBadge({ review }: { review: AdvisoryReview | null | undefined }) {
  if (!review) return null;
  const until = review.expiresAt ? ` until ${review.expiresAt}` : "";
  // The state, expiry and reason also reach screen-reader users, not only a
  // mouse hover.
  return (
    <span
      role="note"
      aria-label={`Dismissed by policy: ${STATE_LABELS[review.state]}${until}, ${review.reason}`}
      title={`${STATE_LABELS[review.state]}${until}: ${review.reason}. Reported, but does not fail the build.`}
      className="inline-flex shrink-0 items-center rounded-full border border-border px-1.5 py-px font-mono text-[9px] font-semibold uppercase tracking-wide text-text-muted"
    >
      Dismissed by policy
    </span>
  );
}
