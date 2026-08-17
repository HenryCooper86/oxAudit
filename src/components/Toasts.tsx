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
            ? "border-red-500/40 text-red-300"
            : t.kind === "success"
              ? "border-emerald-500/40 text-emerald-300"
              : "border-sky-500/40 text-sky-300";
        return (
          <div
            key={t.id}
            className={`pointer-events-auto flex items-start gap-2.5 rounded-lg border bg-ink-850/95 px-3.5 py-3 shadow-xl backdrop-blur ${color}`}
          >
            <Icon size={16} className="mt-0.5 shrink-0" />
            <div className="min-w-0 flex-1 text-xs leading-relaxed text-slate-200">{t.message}</div>
            <button
              onClick={() => dismiss(t.id)}
              className="shrink-0 text-slate-500 hover:text-slate-300"
            >
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
}
