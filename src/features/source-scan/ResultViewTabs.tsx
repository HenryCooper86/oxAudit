import { useRef, type JSX, type KeyboardEvent } from "react";
import type { ResultView } from "./types";

const VIEWS: Array<{ value: ResultView; label: string }> = [
  { value: "open", label: "Open" },
  { value: "otherScopes", label: "Other scopes" },
  { value: "closed", label: "Closed" },
  { value: "resolved", label: "Resolved" },
];

export function ResultViewTabs(props: {
  value: ResultView;
  loading?: boolean;
  counts: Record<ResultView, number>;
  onChange(view: ResultView): void;
}): JSX.Element {
  const { value, counts, onChange, loading } = props;
  const tabs = useRef<Array<HTMLButtonElement | null>>([]);

  const moveFocus = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let next = index;
    if (event.key === "ArrowRight") next = (index + 1) % VIEWS.length;
    else if (event.key === "ArrowLeft") next = (index - 1 + VIEWS.length) % VIEWS.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = VIEWS.length - 1;
    else return;

    event.preventDefault();
    onChange(VIEWS[next].value);
    tabs.current[next]?.focus();
  };

  return (
    <div role="tablist" aria-label="Finding views" className="flex min-w-0 flex-wrap items-center gap-1 border-b border-border px-3 pt-2">
      {VIEWS.map((view, index) => {
        const selected = value === view.value;
        return (
          <button
            key={view.value}
            id={`source-results-tab-${view.value}`}
            type="button"
            role="tab"
            aria-label={`${view.label} ${loading ? "loading" : counts[view.value]}`}
            aria-selected={selected}
            aria-controls="source-results-panel"
            tabIndex={selected ? 0 : -1}
            ref={(node) => {
              tabs.current[index] = node;
            }}
            onClick={() => onChange(view.value)}
            onKeyDown={(event) => moveFocus(event, index)}
            className={`inline-flex h-8 shrink-0 items-center gap-2 border-b-2 px-2 text-[12px] font-medium transition-colors ${selected ? "border-accent text-text-primary" : "border-transparent text-text-muted hover:text-text-primary"}`}
          >
            {view.label}
            <span className={`min-w-5 rounded-full px-1.5 py-0.5 text-center font-mono text-[10px] ${selected ? "bg-accent-subtle text-accent" : "bg-surface-tertiary text-text-muted"}`}>
              {loading ? "…" : counts[view.value]}
            </span>
          </button>
        );
      })}
    </div>
  );
}
