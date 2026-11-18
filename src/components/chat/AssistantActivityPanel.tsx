import { Activity, Bot, CircleDollarSign, ListChecks, PanelRightClose } from "lucide-react";
import type { JSX } from "react";
import type { TodoItem, ToolRecord, UsageSummary } from "../../lib/types";
import { AgentTodoPanel } from "./AgentTodoPanel";
import { ToolCallCard } from "./ToolCallCard";

export function AssistantActivityPanel({
  busy,
  model,
  tools,
  todos,
  usage,
  onClose,
  id = "assistant-activity-panel",
}: {
  busy: boolean;
  model: string | null;
  tools: ToolRecord[];
  todos: TodoItem[];
  usage: UsageSummary | null;
  /** Closes the panel; rendered as the header's close button when given. */
  onClose?: () => void;
  /** The panel's id, the target of the header toggle's `aria-controls`. */
  id?: string;
}): JSX.Element {
  const completedTools = tools.filter((tool) => tool.status === "success").length;

  return (
    <aside
      id={id}
      aria-label="Assistant activity"
      className="flex h-full min-h-0 w-full flex-col bg-surface-secondary"
    >
      <div className="flex h-11 shrink-0 items-center gap-2 border-b border-border pl-4 pr-2">
        <Activity size={14} aria-hidden="true" className="text-accent" />
        <h2 className="text-[10.5px] font-semibold uppercase tracking-[0.08em] text-text-muted">
          Activity
        </h2>
        <span
          className={`ml-auto h-1.5 w-1.5 rounded-full ${busy ? "animate-status-pulse bg-accent" : "bg-text-muted"}`}
          aria-hidden="true"
        />
        <span className="text-[11px] text-text-muted">
          {busy ? "Running" : "Idle"}
        </span>
        {onClose && (
          <button
            type="button"
            aria-label="Close activity"
            title="Close activity"
            onClick={onClose}
            className="ml-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-text-muted transition-colors duration-150 hover:bg-surface-hover hover:text-text-primary"
          >
            <PanelRightClose size={14} aria-hidden="true" />
          </button>
        )}
      </div>

      <div className="m-3 grid shrink-0 grid-cols-3 overflow-hidden rounded-lg border border-border bg-surface-primary">
        <div className="px-2 py-3 text-center">
          <div className="font-mono text-[13px] tabular-nums text-text-primary">
            {tools.length}
          </div>
          <div className="mt-0.5 text-[10px] uppercase tracking-[0.06em] text-text-muted">
            tools
          </div>
        </div>
        <div className="border-x border-border px-2 py-3 text-center">
          <div className="font-mono text-[13px] tabular-nums text-text-primary">
            {completedTools}/{tools.length || 0}
          </div>
          <div className="mt-0.5 text-[10px] uppercase tracking-[0.06em] text-text-muted">
            ok
          </div>
        </div>
        <div className="px-2 py-3 text-center">
          <div className="font-mono text-[13px] tabular-nums text-text-primary">
            {usage ? `${(usage.totalTokens / 1000).toFixed(1)}k` : "—"}
          </div>
          <div className="mt-0.5 text-[10px] uppercase tracking-[0.06em] text-text-muted">
            tokens
          </div>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <section className="border-b border-border px-4 pb-3">
          <div className="mb-2 flex items-center gap-1.5">
            <ListChecks size={12} aria-hidden="true" className="text-text-muted" />
            <h3 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">
              Run plan
            </h3>
          </div>
          {todos.length > 0 ? (
            <AgentTodoPanel items={todos} compact />
          ) : (
            <p className="py-1 text-[12px] leading-relaxed text-text-muted">
              The assistant's plan will appear here when a task needs multiple steps.
            </p>
          )}
        </section>

        <section className="px-4 py-3">
          <div className="mb-2 flex items-center gap-1.5">
            <Bot size={12} aria-hidden="true" className="text-text-muted" />
            <h3 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">
              Recent tools
            </h3>
          </div>
          {tools.length > 0 ? (
            <div className="space-y-1.5">
              {tools.slice(-8).map((tool) => (
                <ToolCallCard key={tool.toolCallId} record={tool} fill />
              ))}
            </div>
          ) : (
            <p className="py-1 text-[12px] leading-relaxed text-text-muted">
              Tool activity will be listed here as the assistant works.
            </p>
          )}
        </section>
      </div>

      <div className="shrink-0 border-t border-border px-4 py-2.5">
        <div className="flex items-center gap-2 text-[11px] text-text-muted">
          <CircleDollarSign size={12} aria-hidden="true" />
          <span className="min-w-0 flex-1 truncate font-mono">
            {model ?? "Model not selected"}
          </span>
          {usage && (
            <span className="shrink-0 font-mono tabular-nums">
              ${usage.costUsd.toFixed(4)}
            </span>
          )}
        </div>
      </div>
    </aside>
  );
}
