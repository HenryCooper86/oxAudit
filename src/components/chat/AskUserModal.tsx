import { useCallback, useEffect, useRef, useState } from "react";
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
  const [submitError, setSubmitError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const skipButtonRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  const skip = useCallback(() => {
    api.respondInteraction(requestId, []).catch(() => undefined);
    onCloseRef.current();
  }, [requestId]);
  const skipActionRef = useRef(skip);
  skipActionRef.current = skip;

  useEffect(() => {
    const timer = setInterval(() => setRemaining((value) => value - 1), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const returnFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const focusFrame = requestAnimationFrame(() => skipButtonRef.current?.focus());

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        skipActionRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusable = Array.from(
        dialog.querySelectorAll<HTMLElement>(
          'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((element) => element.getClientRects().length > 0);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!first || !last) {
        event.preventDefault();
        dialog.focus();
      } else if (event.shiftKey && (document.activeElement === first || !dialog.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !dialog.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      cancelAnimationFrame(focusFrame);
      document.removeEventListener("keydown", onKeyDown);
      requestAnimationFrame(() => {
        if (returnFocus?.isConnected) returnFocus.focus();
      });
    };
  }, []);

  const submit = async () => {
    const payload = questions.map((question, index) => {
      if (question.options?.length) return answers[index] ?? null;
      return freeText[index]?.trim() || null;
    });
    if (payload.every((answer) => answer === null)) return;
    setSubmitError(null);
    try {
      await api.respondInteraction(requestId, payload);
      onClose();
    } catch (error) {
      setSubmitError(String(error));
    }
  };

  const done = questions.every((question, index) =>
    question.options?.length
      ? (answers[index] as string[] | string | undefined) !== undefined
      : !!freeText[index]?.trim(),
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6">
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="ask-user-dialog-title"
        aria-describedby="ask-user-dialog-description"
        className="w-full max-w-lg rounded-lg border border-accent-500/40 bg-ink-850 p-5 shadow-2xl"
      >
        <div className="flex items-center gap-2">
          <HelpCircle size={17} aria-hidden="true" className="text-accent-400" />
          <h3 id="ask-user-dialog-title" className="text-[14px] font-semibold text-stone-100">
            The AI has questions
          </h3>
        </div>
        <p id="ask-user-dialog-description" className="mt-1 text-[12px] leading-relaxed text-stone-400">
          Answer every question to continue, or skip this request.
        </p>
        <div className="mt-3 space-y-4">
          {questions.map((question, index) => (
            <fieldset key={index}>
              <legend className="text-[13px] font-medium leading-relaxed text-stone-200">
                {question.prompt}
              </legend>
              {question.options?.length ? (
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {question.options.map((option) => {
                    const selected = answers[index] as string[] | string | undefined;
                    const isSelected = question.multi_select
                      ? Array.isArray(selected) && selected.includes(option)
                      : selected === option;
                    return (
                      <button
                        key={option}
                        type="button"
                        aria-pressed={isSelected}
                        onClick={() => {
                          setSubmitError(null);
                          setAnswers((previous) => {
                            const next = { ...previous };
                            if (question.multi_select) {
                              const current = (next[index] as string[] | undefined) ?? [];
                              if (isSelected) {
                                const filtered = current.filter((item) => item !== option);
                                if (filtered.length) next[index] = filtered;
                                else delete next[index];
                              } else {
                                next[index] = [...current, option];
                              }
                            } else if (isSelected) {
                              delete next[index];
                            } else {
                              next[index] = option;
                            }
                            return next;
                          });
                        }}
                        className={`rounded-md border px-3 py-1.5 text-[12px] transition-colors ${
                          isSelected
                            ? "border-accent-500/60 bg-accent-500/15 text-accent-300"
                            : "border-ink-600 bg-ink-900 text-stone-300 hover:text-stone-100"
                        }`}
                      >
                        {option}
                      </button>
                    );
                  })}
                </div>
              ) : (
                <input
                  id={`ask-user-answer-${index}`}
                  aria-label={`Answer: ${question.prompt}`}
                  value={freeText[index] ?? ""}
                  onChange={(event) => {
                    setSubmitError(null);
                    setFreeText((previous) => ({ ...previous, [index]: event.target.value }));
                  }}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && done) void submit();
                  }}
                  placeholder="Type your answer…"
                  className="selectable mt-1.5 w-full rounded-md border border-ink-600 bg-ink-950 px-3 py-2 text-[13px] text-stone-200 placeholder:text-stone-500 focus:border-accent-500/70"
                />
              )}
            </fieldset>
          ))}
        </div>
        {submitError && (
          <p role="alert" className="mt-3 text-[12px] leading-relaxed text-red-300">
            {submitError}
          </p>
        )}
        <div className="mt-2 text-right text-[11px] tabular-nums text-stone-400">
          {remaining}s remaining
        </div>
        <div className="mt-3 flex justify-end gap-2">
          <button
            ref={skipButtonRef}
            type="button"
            onClick={skip}
            className="rounded-md border border-ink-600 bg-ink-900 px-3 py-2 text-[12px] text-stone-300 hover:text-stone-100"
          >
            Skip
          </button>
          <button
            type="button"
            onClick={() => void submit()}
            disabled={!done}
            className="rounded-md bg-accent-500 px-4 py-2 text-[12px] font-semibold text-ink-950 hover:bg-accent-400 disabled:opacity-40"
          >
            Answer
          </button>
        </div>
      </div>
    </div>
  );
}
