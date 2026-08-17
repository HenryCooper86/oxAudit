import { useEffect, useState } from "react";
import { HelpCircle } from "lucide-react";
import { api } from "../../lib/api";
import type { AskQuestion } from "../../lib/types";

/**
 * Modal for the AI's `ask_user` tool: renders 1-4 structured questions with
 * optional options and submits the answers back to the pending interaction.
 */
export function AskUserModal({
  requestId,
  questions,
  onClose,
}: {
  requestId: string;
  questions: AskQuestion[];
  onClose: () => void;
}) {
  const [answers, setAnswers] = useState<Record<number, string | string[]>>({});
  const [freeText, setFreeText] = useState<Record<number, string>>({});
  const [remaining, setRemaining] = useState(180);

  useEffect(() => {
    const t = setInterval(() => setRemaining((r) => r - 1), 1000);
    return () => clearInterval(t);
  }, []);

  const submit = async () => {
    const payload = questions.map((q, i) => {
      if (q.options?.length) return answers[i] ?? null;
      return freeText[i]?.trim() || null;
    });
    if (payload.every((a) => a === null)) return;
    try {
      await api.respondInteraction(requestId, payload);
      onClose();
    } catch {
      /* modal stays open */
    }
  };

  const done = questions.every((q, i) =>
    q.options?.length ? (answers[i] as string[] | string | undefined) !== undefined : !!freeText[i]?.trim(),
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6">
      <div className="w-full max-w-lg rounded-xl border border-teal-500/40 bg-ink-850 p-5 shadow-2xl">
        <div className="flex items-center gap-2">
          <HelpCircle size={17} className="text-teal-400" />
          <h3 className="text-sm font-bold text-slate-100">The AI has questions</h3>
        </div>
        <div className="mt-3 space-y-4">
          {questions.map((q, i) => (
            <div key={i}>
              <div className="text-xs font-medium leading-relaxed text-slate-300">{q.prompt}</div>
              {q.options?.length ? (
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {q.options.map((opt) => {
                    const selected = answers[i] as string[] | string | undefined;
                    const isSel = q.multi_select
                      ? Array.isArray(selected) && selected.includes(opt)
                      : selected === opt;
                    return (
                      <button
                        key={opt}
                        onClick={() => {
                          setAnswers((prev) => {
                            const next = { ...prev };
                            if (q.multi_select) {
                              const cur = (next[i] as string[] | undefined) ?? [];
                              if (isSel) {
                                const filtered = cur.filter((x) => x !== opt);
                                if (filtered.length) next[i] = filtered;
                                else delete next[i];
                              } else {
                                next[i] = [...cur, opt];
                              }
                            } else {
                              if (isSel) delete next[i];
                              else next[i] = opt;
                            }
                            return next;
                          });
                        }}
                        className={`rounded-lg border px-3 py-1.5 text-[11px] transition-colors ${
                          isSel
                            ? "border-teal-500/60 bg-teal-500/15 text-teal-300"
                            : "border-ink-600 bg-ink-900 text-slate-400 hover:text-slate-200"
                        }`}
                      >
                        {opt}
                      </button>
                    );
                  })}
                </div>
              ) : (
                <input
                  value={freeText[i] ?? ""}
                  onChange={(e) => setFreeText((prev) => ({ ...prev, [i]: e.target.value }))}
                  onKeyDown={(e) => e.key === "Enter" && done && submit()}
                  placeholder="Type your answer…"
                  className="selectable mt-1.5 w-full rounded-lg border border-ink-600 bg-ink-950 px-3 py-2 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-teal-500/60"
                />
              )}
            </div>
          ))}
        </div>
        <div className="mt-2 text-right text-[10px] tabular-nums text-slate-600">
          {remaining}s remaining
        </div>
        <div className="mt-3 flex justify-end gap-2">
          <button
            onClick={() => {
              api.respondInteraction(requestId, []).catch(() => undefined);
              onClose();
            }}
            className="rounded-lg border border-ink-600 bg-ink-900 px-3 py-2 text-xs text-slate-400 hover:text-slate-200"
          >
            Skip
          </button>
          <button
            onClick={submit}
            disabled={!done}
            className="rounded-lg bg-gradient-to-r from-teal-500 to-emerald-500 px-4 py-2 text-xs font-bold text-ink-950 hover:opacity-90 disabled:opacity-40"
          >
            Answer
          </button>
        </div>
      </div>
    </div>
  );
}
