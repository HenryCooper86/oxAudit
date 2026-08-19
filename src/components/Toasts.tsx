import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";
import { useToastStore } from "../lib/stores";

export function Toasts() {
  const { toasts, dismiss } = useToastStore();
  if (toasts.length === 0) return null;
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-96 flex-col gap-2">
      {toasts.map((t) => {
        const Icon =
          t.kind === "error" ? AlertCircle : t.kind === "success" ? CheckCircle2 : Info;
        const color =
          t.kind === "error"
            ? "border-error-border text-error"
            : t.kind === "success"
              ? "border-success-border text-success"
              : "border-info-border text-info";
        return (
          <div
            key={t.id}
            role={t.kind === "error" ? "alert" : "status"}
            aria-live={t.kind === "error" ? "assertive" : "polite"}
            aria-atomic="true"
            className={`pointer-events-auto flex items-start gap-2.5 rounded-md border bg-surface-secondary px-3.5 py-3 shadow-md backdrop-blur ${color}`}
          >
            <Icon size={16} aria-hidden="true" className="mt-0.5 shrink-0" />
            <div className="min-w-0 flex-1 text-[12px] leading-relaxed text-text-primary">{t.message}</div>
            <button
              type="button"
              aria-label="Dismiss notification"
              onClick={() => dismiss(t.id)}
              className="shrink-0 rounded-sm text-text-muted hover:text-text-primary"
            >
              <X size={14} aria-hidden="true" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
