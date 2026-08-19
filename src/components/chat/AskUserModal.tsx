import { useCallback, useEffect, useRef, useState } from "react";
import { HelpCircle } from "lucide-react";
import { api } from "../../lib/api";
import type { AskQuestion } from "../../lib/types";
import { Button } from "../ui";

/**
 * Modal for the AI's `ask_user` tool: renders 1-4 structured questions with
 * optional options and submits the answers back to the pending interaction.
 */
export function AskUserModal({
  requestId,
  questions,
  onClose,
  onRestoreFocus,
}: {
  requestId: string;
  questions: AskQuestion[];
  onClose: () => void;
  onRestoreFocus: () => void;
}) {
  const [answers, setAnswers] = useState<Record<number, string | string[]>>({});
  const [freeText, setFreeText] = useState<Record<number, string>>({});
  const [remaining, setRemaining] = useState(180);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const skipButtonRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  const onRestoreFocusRef = useRef(onRestoreFocus);
  onRestoreFocusRef.current = onRestoreFocus;

  const skip = useCallback(() => {
    api.respondInteraction(requestId, []).catch(() => undefined);
    onCloseRef.current();
  }, [requestId]);
  const skipActionRef = useRef(skip);
  skipActionRef.current = skip;

  useEffect(() => {
    const timer = setInterval(
      () => setRemaining((value) => Math.max(0, value - 1)),
      1000,
    );
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (remaining === 0) skipActionRef.current();
  }, [remaining]);

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
        if (returnFocus?.isConnected && returnFocus !== document.body) {
          returnFocus.focus();
          if (document.activeElement === returnFocus) return;
        }
        onRestoreFocusRef.current();
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
        className="w-full max-w-lg rounded-md border border-accent-glow bg-surface-secondary p-5 shadow-lg"
      >
        <div className="flex items-center gap-2">
          <HelpCircle size={17} aria-hidden="true" className="text-accent" />
          <h3 id="ask-user-dialog-title" className="text-[14px] font-semibold text-text-primary">
            The AI has questions
          </h3>
        </div>
        <p id="ask-user-dialog-description" className="mt-1 text-[12px] leading-relaxed text-text-muted">
          Answer every question to continue, or skip this request.
        </p>
        <div className="mt-3 space-y-4">
          {questions.map((question, index) => (
            <fieldset key={index}>
              <legend className="text-[13px] font-medium leading-relaxed text-text-primary">
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
                        className={`rounded-sm border px-3 py-1.5 text-[12px] transition-colors ${ isSelected ? "border-accent-glow bg-accent-subtle text-accent" : "border-border bg-surface-secondary text-text-secondary hover:text-text-primary" }`}
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
                  className="selectable mt-1.5 w-full rounded-sm border border-border bg-surface-primary px-3 py-2 text-[13px] text-text-primary placeholder:text-text-muted focus:border-accent"
                />
              )}
            </fieldset>
          ))}
        </div>
        {submitError && (
          <p role="alert" className="mt-3 text-[12px] leading-relaxed text-error">
            {submitError}
          </p>
        )}
        <div className="mt-2 text-right text-[11px] tabular-nums text-text-muted">
          {remaining}s remaining
        </div>
        <div className="mt-3 flex justify-end gap-2">
          <Button
            ref={skipButtonRef}
            type="button"
            onClick={skip}
            variant="ghost"
            size="md"
          >
            Skip
          </Button>
          <button
            type="button"
            onClick={() => void submit()}
            disabled={!done}
            className="rounded-sm bg-accent px-4 py-2 text-[12px] font-semibold text-accent-contrast hover:bg-accent-hover disabled:opacity-40"
          >
            Answer
          </button>
        </div>
      </div>
    </div>
  );
}
