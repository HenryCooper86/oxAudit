import { useState } from "react";
import { AlertTriangle, Bot, ChevronDown, FileCode2, KeyRound } from "lucide-react";
import { api } from "../lib/api";
import { severityColor } from "../lib/format";
import { useAppStore, useToastStore } from "../lib/stores";
import type { ChatResponse, Finding } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";
import Markdown from "react-markdown";

export function FindingCard({ finding, fileIndex }: { finding: Finding; fileIndex?: number }) {
  const [open, setOpen] = useState(false);
  const [ai, setAi] = useState<{ loading: boolean; result: ChatResponse | null; error: string | null }>({
    loading: false,
    result: null,
    error: null,
  });
  const push = useToastStore((s) => s.push);
  const aiReady = useAppStore((s) => s.aiReady);

  const runAi = async () => {
    if (ai.loading) return;
    if (!aiReady) {
      push("error", "AI is not configured — enable it in Settings first.");
      return;
    }
    setAi({ loading: true, result: null, error: null });
    try {
      const res = await api.analyzeFinding(finding);
      setAi({ loading: false, result: res, error: null });
    } catch (e) {
      setAi({ loading: false, result: null, error: String(e) });
    }
  };

  const isSecret = finding.category === "secret";
  const Icon = isSecret ? KeyRound : FileCode2;

  return (
    <div className="overflow-hidden rounded-xl border border-ink-700 bg-ink-850 transition-colors hover:border-ink-600">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left"
      >
        <span
          className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border ${severityColor(finding.severity)}`}
        >
          <Icon size={14} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] font-semibold text-slate-100">{finding.ruleName}</span>
            <SeverityBadge severity={finding.severity} />
            {finding.cwe && (
              <span className="rounded border border-ink-600 bg-ink-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                {finding.cwe}
              </span>
            )}
            {isSecret && finding.entropy !== null && (
              <span className="rounded border border-ink-600 bg-ink-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                entropy {finding.entropy.toFixed(2)}
              </span>
            )}
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[11px] text-slate-500">
            <span className="max-w-[420px] truncate">{finding.filePath}</span>
            <span>:{finding.line}</span>
            {finding.language && (
              <span className="rounded bg-ink-800 px-1 text-[10px] uppercase text-slate-500">
                {finding.language}
              </span>
            )}
            {fileIndex !== undefined && (
              <span className="rounded bg-ink-800 px-1 text-[10px] text-slate-600">#{fileIndex}</span>
            )}
          </div>
        </div>
        <ChevronDown
          size={16}
          className={`mt-1 shrink-0 text-slate-500 transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>

      {open && (
        <div className="border-t border-ink-800 px-4 pb-4 pt-3">
          <p className="text-xs leading-relaxed text-slate-400">{finding.description}</p>

          <div className="selectable mt-3 overflow-x-auto rounded-lg border border-ink-700 bg-ink-950 p-3">
            <div className="mb-1.5 flex items-center gap-2 text-[10px] uppercase tracking-wider text-slate-600">
              <AlertTriangle size={11} />
              match
            </div>
            <pre className="whitespace-pre-wrap break-all font-mono text-[11px] leading-relaxed text-orange-300/90">
              {finding.matchText}
            </pre>
          </div>

          {finding.context && (
            <div className="selectable mt-2 overflow-x-auto rounded-lg border border-ink-800 bg-ink-950 p-3">
              <pre className="font-mono text-[11px] leading-relaxed text-slate-400">
                {finding.context}
              </pre>
            </div>
          )}

          <div className="mt-3 rounded-lg border border-emerald-900/50 bg-emerald-950/20 px-3 py-2.5">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-emerald-500/80">
              Recommendation
            </div>
            <p className="mt-1 text-xs leading-relaxed text-slate-300">{finding.recommendation}</p>
          </div>

          <div className="mt-3 flex items-center gap-2">
            <button
              onClick={runAi}
              disabled={ai.loading}
              className="inline-flex items-center gap-1.5 rounded-lg border border-teal-500/40 bg-teal-500/10 px-3 py-1.5 text-xs font-medium text-teal-300 transition-colors hover:bg-teal-500/20 disabled:opacity-50"
            >
              <Bot size={13} />
              {ai.loading ? "Analyzing…" : ai.result ? "Re-analyze" : "Ask AI to analyze"}
            </button>
            {ai.error && <span className="text-[11px] text-red-400">{ai.error}</span>}
          </div>

          {ai.loading && (
            <div className="mt-3 animate-pulse rounded-lg border border-ink-700 bg-ink-900 px-3 py-2 text-[11px] text-slate-500">
              Consulting the model… this can take 10–60s.
            </div>
          )}
          {ai.result && (
            <div className="md-body selectable mt-3 max-h-96 overflow-y-auto rounded-lg border border-ink-700 bg-ink-900 px-4 py-3 text-xs">
              <Markdown>{ai.result.content}</Markdown>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
