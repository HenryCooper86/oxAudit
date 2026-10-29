import { useEffect, useState } from "react";
import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";
import { useToastStore, type Toast } from "../lib/stores";

export function Toasts() {
  const toasts = useToastStore((state) => state.toasts);
  if (toasts.length === 0) return null;
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-[calc(100vw-2rem)] max-w-96 flex-col gap-2">
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} />
      ))}
    </div>
  );
}

function ToastItem({ toast }: { toast: Toast }) {
  const dismiss = useToastStore((state) => state.dismiss);
  const pause = useToastStore((state) => state.pause);
  const resume = useToastStore((state) => state.resume);
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const paused = hovered || focused;

  useEffect(() => {
    if (paused) pause(toast.id);
    else resume(toast.id);
  }, [paused, pause, resume, toast.id]);

  const Icon =
    toast.kind === "error" ? AlertCircle : toast.kind === "success" ? CheckCircle2 : Info;
  const color =
    toast.kind === "error"
      ? "border-error-border text-error"
      : toast.kind === "success"
        ? "border-success-border text-success"
        : "border-info-border text-info";
  return (
    <div
      role={toast.kind === "error" ? "alert" : "status"}
      aria-live={toast.kind === "error" ? "assertive" : "polite"}
      aria-atomic="true"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onFocus={() => setFocused(true)}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setFocused(false);
      }}
      className={`pointer-events-auto flex items-start gap-2.5 rounded-md border bg-surface-secondary px-3.5 py-3 shadow-md backdrop-blur ${color}`}
    >
      <Icon size={16} aria-hidden="true" className="mt-0.5 shrink-0" />
      <div className="min-w-0 flex-1 break-words text-[12px] leading-relaxed text-text-primary">{toast.message}</div>
      <button
        type="button"
        aria-label="Dismiss notification"
        onClick={() => dismiss(toast.id)}
        className="shrink-0 rounded-sm text-text-muted hover:text-text-primary"
      >
        <X size={14} aria-hidden="true" />
      </button>
    </div>
  );
}
