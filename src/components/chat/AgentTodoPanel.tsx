import { Check, ListChecks } from "lucide-react";
import { useState, type JSX } from "react";
import type { TodoItem } from "../../lib/types";

/**
 * The agent's working plan for the current conversation, as maintained by the
 * `todo` tool. Collapsible because a long plan would otherwise crowd out the
 * transcript, and collapsed it still shows the done/total count.
 */
export function AgentTodoPanel({ items }: { items: TodoItem[] }): JSX.Element | null {
  const [open, setOpen] = useState(true);

  if (items.length === 0) return null;

  const done = items.filter((item) => item.status === "done").length;
  const complete = done === items.length;

  return (
    <section
      aria-label="Agent plan"
      className="rounded-sm border border-border bg-surface-secondary"
    >
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 px-3 py-2 text-left"
      >
        <ListChecks
          size={13}
          aria-hidden="true"
          className={complete ? "text-success" : "text-accent"}
        />
        <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-text-muted">
          Plan
        </span>
        <span className="ml-auto font-mono text-[11px] tabular-nums text-text-muted">
          {done}/{items.length}
        </span>
      </button>

      {open && (
        <ul className="space-y-1 border-t border-border px-3 py-2">
          {items.map((item) => {
            const finished = item.status === "done";
            return (
              <li key={item.id} className="flex items-start gap-2 text-[12px] leading-relaxed">
                <span
                  aria-hidden="true"
                  className={`mt-0.5 flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-sm border ${
                    finished
                      ? "border-success-border bg-success-subtle text-success"
                      : "border-border"
                  }`}
                >
                  {finished && <Check size={9} strokeWidth={3} />}
                </span>
                <span
                  className={finished ? "text-text-muted line-through" : "text-text-secondary"}
                >
                  {item.text}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
