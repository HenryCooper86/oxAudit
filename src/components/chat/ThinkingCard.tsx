import { useEffect, useId, useState } from "react";
import { Brain, ChevronDown } from "lucide-react";

/**
 * Live "Thinking…" block while the model streams reasoning content
 * (o1/R1-style `reasoning_content`), collapsing to a static expandable
 * "Thought" once the answer starts. Modeled on y-gui's ThinkingCard.
 */
export function ThinkingCard({
  text,
  streaming,
}: {
  text: string;
  streaming: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [finishedAt, setFinishedAt] = useState<number | null>(null);
  const detailsId = useId();

  useEffect(() => {
    if (streaming) {
      setFinishedAt(null);
      const t = setInterval(() => setElapsed((e) => e + 1), 1000);
      return () => clearInterval(t);
    }
    setFinishedAt((prev) => prev ?? elapsed);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [streaming]);

  const hasContent = text.trim().length > 0;
  const duration = finishedAt ?? elapsed;

  return (
    <div className="selectable mb-1 overflow-hidden rounded-sm border border-border bg-surface-secondary">
      <button
        type="button"
        aria-expanded={hasContent ? open : undefined}
        aria-controls={hasContent ? detailsId : undefined}
        onClick={() => hasContent && setOpen(!open)}
        className={`flex w-full items-center gap-2 px-3.5 py-2.5 text-left ${ hasContent ? "cursor-pointer hover:bg-surface-hover" : "cursor-default" }`}
      >
        <span className="relative flex h-2 w-2">
          {streaming && (
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-60" />
          )}
          <span
            className={`relative inline-flex h-2 w-2 rounded-full ${ streaming ? "bg-accent" : "bg-text-muted" }`}
          />
        </span>
        <span className="text-[12px] font-semibold uppercase tracking-wider text-text-secondary">
          {streaming ? "Thinking" : "Thought"}
          {streaming ? `… ${elapsed}s` : duration > 0 ? ` · ${duration}s` : ""}
        </span>
        {hasContent && (
          <ChevronDown
            size={13}
            aria-hidden="true"
            className={`ml-auto text-text-muted transition-transform ${open ? "rotate-180" : ""}`}
          />
        )}
        {!hasContent && streaming && (
          <Brain size={13} aria-hidden="true" className="ml-auto text-text-muted" />
        )}
      </button>
      {hasContent && open && (
        <div id={detailsId} className="border-t border-border px-4 py-3">
          <pre className="whitespace-pre-wrap font-mono text-[13px] leading-relaxed text-text-secondary">
            {text}
          </pre>
        </div>
      )}
    </div>
  );
}
