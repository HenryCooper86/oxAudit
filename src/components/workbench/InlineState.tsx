import { AlertCircle, CircleOff, LoaderCircle, SearchX } from "lucide-react";
import type { JSX, ReactNode } from "react";

const TONE_STYLES = {
  idle: "border-border bg-surface-secondary text-text-muted",
  running: "border-accent-glow bg-accent-subtle text-accent",
  empty: "border-border bg-surface-secondary text-text-muted",
  error: "border-error-border bg-error-subtle text-error",
  unavailable: "border-warning-border bg-warning-subtle text-warning",
} as const;

const TONE_ICON = {
  idle: SearchX,
  running: LoaderCircle,
  empty: SearchX,
  error: AlertCircle,
  unavailable: CircleOff,
} as const;

export function InlineState(props: {
  tone: "idle" | "running" | "empty" | "error" | "unavailable";
  title: string;
  description?: string;
  action?: ReactNode;
  progress?: ReactNode;
  compact?: boolean;
}): JSX.Element {
  const { tone, title, description, action, progress, compact = false } = props;
  const Icon = TONE_ICON[tone];

  return (
    <div
      role={tone === "error" ? "alert" : progress ? undefined : "status"}
      className={`border ${TONE_STYLES[tone]} ${compact ? "px-3 py-2.5" : "px-4 py-4"}`}
    >
      <div className="flex items-start gap-3">
        <Icon
          size={compact ? 15 : 17}
          aria-hidden="true"
          className={`mt-0.5 shrink-0 ${tone === "running" ? "animate-spin" : ""}`}
        />
        <div className="min-w-0 flex-1">
          <p className="text-[13px] font-medium text-text-primary">{title}</p>
          {description && <p className="mt-0.5 text-[12px] leading-relaxed text-text-muted">{description}</p>}
          {progress && <div className="mt-2.5">{progress}</div>}
          {action && <div className="mt-2.5 flex flex-wrap items-center gap-2">{action}</div>}
        </div>
      </div>
    </div>
  );
}
