import { useEffect, useState } from "react";
import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";
import { useToastStore, type Toast } from "../lib/stores";

export function Toasts() {
  const toasts = useToastStore((state) => state.toasts);
  if (toasts.length === 0) return null;
  return (
    <div className="pointer-events-none fixed bottom-10 right-4 z-50 flex w-[calc(100vw-2rem)] max-w-96 flex-col gap-2">
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
  // oxFuzz's toast: a card that slides up, its border taking the tone.
  const color =
    toast.kind === "error"
      ? "border-error text-error"
      : toast.kind === "success"
        ? "border-success text-success"
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
      className={`surface-card pointer-events-auto flex animate-slide-in-up items-start gap-2.5 px-4 py-2.5 shadow-md ${color}`}
    >
      <Icon size={16} aria-hidden="true" className="mt-0.5 shrink-0" />
      <div className="min-w-0 flex-1 break-words text-[12px] leading-relaxed text-text-primary">{toast.message}</div>
      <button
        type="button"
        aria-label="Dismiss notification"
        onClick={() => dismiss(toast.id)}
        className="inline-flex h-[22px] w-[22px] shrink-0 items-center justify-center rounded-sm text-text-muted hover:bg-surface-active hover:text-text-primary"
      >
        <X size={13} aria-hidden="true" />
      </button>
    </div>
  );
}
