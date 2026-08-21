import { useEffect, useId, useState } from "react";
import { ChevronRight } from "lucide-react";

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
    <div className="selectable my-1">
      <button
        type="button"
        aria-expanded={hasContent ? open : undefined}
        aria-controls={hasContent ? detailsId : undefined}
        onClick={() => hasContent && setOpen(!open)}
        className={`inline-flex items-center gap-1.5 rounded-sm py-1 pr-1.5 text-left text-text-muted ${ hasContent ? "cursor-pointer hover:text-text-secondary" : "cursor-default" }`}
      >
        <span className="relative flex h-2 w-2">
          {streaming && (
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-60" />
          )}
          <span
            className={`relative inline-flex h-2 w-2 rounded-full ${ streaming ? "bg-accent" : "bg-text-muted" }`}
          />
        </span>
        <span className="text-[12px] font-medium text-text-muted">
          {streaming ? "Thinking" : "Thought"}
          {streaming ? `… ${elapsed}s` : duration > 0 ? ` · ${duration}s` : ""}
        </span>
        {hasContent && (
          <ChevronRight
            size={12}
            aria-hidden="true"
            className={`text-text-muted transition-transform ${open ? "rotate-90" : ""}`}
          />
        )}
      </button>
      {hasContent && open && (
        <div id={detailsId} className="mt-1 rounded-md bg-surface-secondary px-3 py-2.5">
          <pre className="max-h-80 overflow-y-auto whitespace-pre-wrap font-sans text-[13px] leading-relaxed text-text-secondary">
            {text}
          </pre>
        </div>
      )}
    </div>
  );
}
