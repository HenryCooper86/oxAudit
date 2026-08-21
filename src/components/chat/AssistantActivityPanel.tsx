import { Activity, Bot, CircleDollarSign, ListChecks } from "lucide-react";
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
}: {
  busy: boolean;
  model: string | null;
  tools: ToolRecord[];
  todos: TodoItem[];
  usage: UsageSummary | null;
}): JSX.Element {
  const completedTools = tools.filter((tool) => tool.status === "success").length;

  return (
    <aside
      id="assistant-activity-panel"
      aria-label="Assistant activity"
      className="flex w-[292px] shrink-0 flex-col border-l border-border bg-surface-secondary max-[1180px]:hidden"
    >
      <header className="flex h-[52px] shrink-0 items-center gap-2 border-b border-border px-3.5">
        <Activity size={14} aria-hidden="true" className="text-accent" />
        <h2 className="text-[12px] font-semibold uppercase tracking-[0.08em] text-text-secondary">
          Activity
        </h2>
        <span
          className={`ml-auto h-1.5 w-1.5 rounded-full ${busy ? "animate-pulse bg-accent" : "bg-text-muted"}`}
          aria-hidden="true"
        />
        <span className="text-[11px] text-text-muted">
          {busy ? "Running" : "Idle"}
        </span>
      </header>

      <div className="grid shrink-0 grid-cols-3 border-b border-border">
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
        <section className="border-b border-border px-3 py-3">
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

        <section className="px-3 py-3">
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
              Approved tool activity will be listed here as the assistant works.
            </p>
          )}
        </section>
      </div>

      <footer className="shrink-0 border-t border-border px-3 py-2.5">
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
      </footer>
    </aside>
  );
}
