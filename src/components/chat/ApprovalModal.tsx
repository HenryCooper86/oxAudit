import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";

/**
 * HITL permission approval modal (y-agent hitl.rs): a tool call is waiting for
 * the user's Approve / Deny. Auto-denies after 120s (mirrors the Rust timeout).
 */
export function ApprovalModal({
  tool,
  argumentsPreview,
  onDecide,
}: {
  tool: string;
  argumentsPreview: string;
  onDecide: (approve: boolean) => void;
}) {
  const [remaining, setRemaining] = useState(120);
  useEffect(() => {
    const t = setInterval(() => setRemaining((r) => r - 1), 1000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    if (remaining <= 0) onDecide(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [remaining]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6">
      <div className="w-full max-w-md rounded-xl border border-amber-500/40 bg-ink-850 p-5 shadow-2xl">
        <div className="flex items-center gap-2">
          <ShieldAlert size={17} className="text-amber-400" />
          <h3 className="text-sm font-bold text-slate-100">Tool permission required</h3>
        </div>
        <p className="mt-2 text-xs leading-relaxed text-slate-400">
          The AI wants to call{" "}
          <span className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[11px] text-teal-300">
            {tool}
          </span>
          . Approve to let it run, or deny to skip it.
        </p>
        {argumentsPreview && (
          <pre className="selectable mt-3 max-h-40 overflow-y-auto whitespace-pre-wrap break-all rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 font-mono text-[10px] leading-relaxed text-slate-400">
            {argumentsPreview}
          </pre>
        )}
        <div className="mt-2 text-right text-[10px] tabular-nums text-slate-600">
          auto-denies in {remaining}s
        </div>
        <div className="mt-3 grid grid-cols-2 gap-2">
          <button
            onClick={() => onDecide(false)}
            className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs font-semibold text-red-300 hover:bg-red-500/20"
          >
            Deny
          </button>
          <button
            onClick={() => onDecide(true)}
            className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs font-semibold text-emerald-300 hover:bg-emerald-500/20"
          >
            Approve
          </button>
        </div>
      </div>
    </div>
  );
}
