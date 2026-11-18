import { AlertCircle, AlertTriangle, CircleOff, LoaderCircle } from "lucide-react";
import type { JSX, ReactNode } from "react";

type Tone = "warning" | "error" | "info" | "progress";

const TONE = {
  warning: { stripe: "border-l-warning", icon: AlertTriangle, iconClass: "text-warning" },
  error: { stripe: "border-l-error", icon: AlertCircle, iconClass: "text-error" },
  info: { stripe: "border-l-border-strong", icon: CircleOff, iconClass: "text-text-muted" },
  progress: { stripe: "border-l-accent", icon: LoaderCircle, iconClass: "animate-spin text-accent" },
} as const;

/**
 * An inline notice above the composer, in oxFuzz's notice shape (phase 1's
 * `InlineState`): a flat card with a 3px status stripe on the left. The role
 * is the caller's, because the Assistant announces some states as alerts that
 * are not errors (a server build without AI, a readiness lookup that failed).
 */
export function AssistantNotice({
  role,
  tone,
  title,
  children,
  action,
}: {
  role: "status" | "alert";
  tone: Tone;
  title: string;
  children: ReactNode;
  action?: ReactNode;
}): JSX.Element {
  const { stripe, icon: Icon, iconClass } = TONE[tone];
  return (
    <div
      role={role}
      className={`surface-card flex items-start gap-2.5 border-l-[3px] ${stripe} px-3 py-2 shadow-none`}
    >
      <Icon size={15} aria-hidden="true" className={`mt-px shrink-0 ${iconClass}`} />
      <div className="min-w-0 flex-1 text-[12px] leading-relaxed">
        <p className="font-medium text-text-primary">{title}</p>
        <p className="text-text-secondary [overflow-wrap:anywhere]">{children}</p>
      </div>
      {action && <div className="shrink-0 self-center">{action}</div>}
    </div>
  );
}
