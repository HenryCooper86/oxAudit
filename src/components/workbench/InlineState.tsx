import { AlertCircle, CircleOff, LoaderCircle, SearchX } from "lucide-react";
import type { JSX, ReactNode } from "react";

type Tone = "idle" | "running" | "empty" | "error" | "unavailable";

const TONE_ICON = {
  idle: SearchX,
  running: LoaderCircle,
  empty: SearchX,
  error: AlertCircle,
  unavailable: CircleOff,
} as const;

/** The 3px left stripe and icon colour of an inline notice, after oxFuzz's project bar. */
const NOTICE_TONE = {
  idle: { stripe: "border-l-border-strong", icon: "text-text-muted" },
  empty: { stripe: "border-l-border-strong", icon: "text-text-muted" },
  running: { stripe: "border-l-accent", icon: "text-accent" },
  error: { stripe: "border-l-error", icon: "text-error" },
  unavailable: { stripe: "border-l-warning", icon: "text-warning" },
} as const;

/**
 * Page and panel states, in oxFuzz's two shapes.
 *
 * - Idle and empty (not compact): oxFuzz's EmptyState, a centred card with a
 *   48px icon circle, a title, a hint and an optional action.
 * - Running, error and unavailable, and every compact state: an inline notice,
 *   a card with a 3px status stripe on the left.
 *
 * Roles do not change with the shape: errors are alerts, progress is left to
 * the caller's own live region, everything else is a status.
 */
export function InlineState(props: {
  tone: Tone;
  title: string;
  description?: string;
  action?: ReactNode;
  progress?: ReactNode;
  compact?: boolean;
}): JSX.Element {
  const { tone, title, description, action, progress, compact = false } = props;
  const Icon = TONE_ICON[tone];
  const role = tone === "error" ? "alert" : progress ? undefined : "status";

  if (!compact && (tone === "idle" || tone === "empty")) {
    return (
      <div role={role} className="surface-card flex flex-col items-center justify-center px-4 py-10 text-center">
        <span
          aria-hidden="true"
          className="mb-3 inline-flex h-12 w-12 items-center justify-center rounded-full border border-border bg-accent-subtle text-accent"
        >
          <Icon size={20} />
        </span>
        <p className="text-[13px] font-medium text-text-primary">{title}</p>
        {description && (
          <p className="mt-1 max-w-md text-[13px] leading-relaxed text-text-secondary">{description}</p>
        )}
        {progress && <div className="mt-3 w-full max-w-md">{progress}</div>}
        {action && <div className="mt-4 flex flex-wrap items-center justify-center gap-2">{action}</div>}
      </div>
    );
  }

  const notice = NOTICE_TONE[tone];
  return (
    <div
      role={role}
      className={`surface-card border-l-[3px] ${notice.stripe} ${compact ? "px-3 py-2.5" : "px-4 py-3.5"}`}
    >
      <div className="flex items-start gap-3">
        <Icon
          size={compact ? 15 : 16}
          aria-hidden="true"
          className={`mt-0.5 shrink-0 ${notice.icon} ${tone === "running" ? "animate-spin" : ""}`}
        />
        <div className="min-w-0 flex-1">
          <p className="text-[13px] font-medium text-text-primary">{title}</p>
          {description && <p className="mt-0.5 text-[12px] leading-relaxed text-text-secondary">{description}</p>}
          {progress && <div className="mt-2.5">{progress}</div>}
          {action && <div className="mt-2.5 flex flex-wrap items-center gap-2">{action}</div>}
        </div>
      </div>
    </div>
  );
}
