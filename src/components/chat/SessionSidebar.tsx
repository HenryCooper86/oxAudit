import { useEffect, useState } from "react";
import { Check, MessageSquare, Pencil, Plus, Search, Trash2, X } from "lucide-react";
import { fmtDate } from "../../lib/format";
import type { SessionInfo } from "../../lib/types";

/**
 * Session list sidebar (y-gui ChatSidebarPanel, trimmed): search, active
 * highlight, streaming dot, inline rename, two-step delete, new chat.
 */
export function SessionSidebar({
  sessions,
  activeId,
  busy,
  disabled = false,
  onSelect,
  onCreate,
  onRename,
  onDelete,
}: {
  sessions: SessionInfo[];
  activeId: string | null;
  busy: boolean;
  disabled?: boolean;
  onSelect: (id: string) => void;
  onCreate: () => void;
  onRename: (id: string, title: string) => void;
  onDelete: (id: string) => void;
}) {
  const controlsDisabled = busy || disabled;
  const [query, setQuery] = useState("");
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  useEffect(() => {
    if (renamingId) {
      const s = sessions.find((x) => x.id === renamingId);
      if (s) setRenameValue(s.title);
    }
  }, [renamingId, sessions]);

  const filtered = query.trim()
    ? sessions.filter((s) => s.title.toLowerCase().includes(query.trim().toLowerCase()))
    : sessions;

  const commitRename = () => {
    if (renamingId && renameValue.trim()) {
      onRename(renamingId, renameValue.trim());
    }
    setRenamingId(null);
  };

  return (
    <aside
      aria-label="Chat sessions"
      className="flex w-60 shrink-0 flex-col border-r border-border bg-surface-secondary"
    >
      <div className="p-3">
        <button
          type="button"
          onClick={onCreate}
          disabled={controlsDisabled}
          className="flex w-full items-center gap-2 rounded-sm border border-transparent px-2.5 py-[7px] text-left text-[13px] leading-tight font-medium text-text-primary transition-colors duration-150 hover:bg-accent-subtle disabled:cursor-not-allowed disabled:opacity-40"
        >
          <span className="inline-flex h-[18px] w-[18px] shrink-0 items-center justify-center text-accent">
            <Plus size={15} aria-hidden="true" />
          </span>
          New chat
        </button>
        <label className="relative mt-2 block">
          <span className="sr-only">Search chat sessions</span>
          <Search
            size={12}
            aria-hidden="true"
            className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted"
          />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search sessions…"
            className="w-full rounded-sm border border-border bg-surface-primary py-1.5 pl-8 pr-2 text-[13px] text-text-primary outline-none placeholder:text-text-muted focus:border-accent"
          />
        </label>
      </div>

      <div className="flex-1 space-y-0.5 overflow-y-auto px-2 pb-3">
        {filtered.length === 0 && (
          <div className="px-3 py-6 text-center text-[12px] text-text-muted">
            {sessions.length === 0 ? "No chats yet" : "No matches"}
          </div>
        )}
        {filtered.map((s) => {
          const active = s.id === activeId;
          return (
            <div
              key={s.id}
              className={`group relative rounded-sm px-2.5 py-2 transition-colors ${ active ? "bg-surface-active" : "hover:bg-surface-hover" }`}
            >
              {renamingId === s.id ? (
                <div className="flex items-center gap-1">
                  <input
                    autoFocus
                    aria-label={`Rename ${s.title}`}
                    value={renameValue}
                    onChange={(e) => setRenameValue(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") commitRename();
                      if (e.key === "Escape") setRenamingId(null);
                    }}
                    className="min-w-0 flex-1 rounded-sm border border-accent-glow bg-surface-primary px-1.5 py-0.5 text-[13px] text-text-primary outline-none"
                  />
                  <button
                    type="button"
                    aria-label="Save session name"
                    onClick={commitRename}
                    className="text-success"
                  >
                    <Check size={12} aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    aria-label="Cancel session rename"
                    onClick={() => setRenamingId(null)}
                    className="text-text-muted"
                  >
                    <X size={12} aria-hidden="true" />
                  </button>
                </div>
              ) : confirmDeleteId === s.id ? (
                <div className="flex items-center gap-1.5 text-[12px]">
                  <span className="text-text-muted">Delete?</span>
                  <button
                    type="button"
                    onClick={() => {
                      onDelete(s.id);
                      setConfirmDeleteId(null);
                    }}
                    className="rounded-sm bg-transparent px-1.5 py-0.5 text-error hover:bg-error-subtle"
                  >
                    Yes
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmDeleteId(null)}
                    className="rounded-sm bg-surface-tertiary px-1.5 py-0.5 text-text-muted hover:text-text-primary"
                  >
                    No
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={() => !controlsDisabled && onSelect(s.id)}
                  disabled={controlsDisabled}
                  aria-current={active ? "true" : undefined}
                  className="flex w-full items-start gap-2 text-left disabled:cursor-default"
                >
                  <MessageSquare
                    size={12}
                    aria-hidden="true"
                    className={`mt-0.5 shrink-0 ${active ? "text-accent" : "text-text-muted"}`}
                  />
                  <span className="min-w-0 flex-1">
                    <span
                      className={`block truncate text-[12px] font-medium ${ active ? "text-text-primary" : "text-text-muted" }`}
                    >
                      {s.title}
                    </span>
                    <span className="block text-[11px] text-text-muted">
                      {fmtDate(s.updatedAt)}
                      {s.messageCount > 0 ? ` · ${s.messageCount} msg` : ""}
                    </span>
                  </span>
                  {active && busy && (
                    <span
                      role="status"
                      aria-label="Assistant is responding"
                      className="mt-1 h-1.5 w-1.5 shrink-0 animate-pulse rounded-full bg-accent"
                    />
                  )}
                </button>
              )}

              {!controlsDisabled && renamingId !== s.id && confirmDeleteId !== s.id && (
                <div className="absolute right-1.5 top-1.5 hidden items-center gap-0.5 group-hover:flex group-focus-within:flex">
                  <button
                    type="button"
                    aria-label={`Rename ${s.title}`}
                    onClick={() => setRenamingId(s.id)}
                    className="rounded-sm bg-surface-tertiary p-0.5 text-text-muted hover:text-text-primary"
                    title="Rename"
                  >
                    <Pencil size={11} aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    aria-label={`Delete ${s.title}`}
                    onClick={() => setConfirmDeleteId(s.id)}
                    className="rounded-sm bg-surface-tertiary p-0.5 text-text-muted hover:text-error"
                    title="Delete"
                  >
                    <Trash2 size={11} aria-hidden="true" />
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </aside>
  );
}
