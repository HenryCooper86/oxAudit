import { useEffect, useRef, useState } from "react";
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
  const [searchOpen, setSearchOpen] = useState(false);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (renamingId) {
      const s = sessions.find((x) => x.id === renamingId);
      if (s) setRenameValue(s.title);
    }
  }, [renamingId, sessions]);

  useEffect(() => {
    if (searchOpen) searchRef.current?.focus();
  }, [searchOpen]);

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
      className="flex w-[216px] shrink-0 flex-col border-r border-border bg-surface-secondary max-[1040px]:w-[196px]"
    >
      <div className="flex h-[52px] shrink-0 items-center gap-1 border-b border-border px-2.5">
        <button
          type="button"
          onClick={onCreate}
          disabled={controlsDisabled}
          className="flex min-w-0 flex-1 items-center gap-2 rounded-sm border border-transparent px-2 py-[7px] text-left text-[13px] leading-tight font-medium text-text-primary transition-colors duration-150 hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-40"
        >
          <span className="inline-flex h-[18px] w-[18px] shrink-0 items-center justify-center text-accent">
            <Plus size={15} aria-hidden="true" />
          </span>
          New chat
        </button>
        <button
          type="button"
          aria-label={searchOpen ? "Close session search" : "Search chat sessions"}
          aria-expanded={searchOpen}
          onClick={() => {
            setSearchOpen((open) => !open);
            if (searchOpen) setQuery("");
          }}
          className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-sm text-text-muted transition-colors hover:bg-surface-hover hover:text-text-primary ${searchOpen ? "bg-surface-active text-text-primary" : ""}`}
        >
          {searchOpen ? <X size={13} aria-hidden="true" /> : <Search size={13} aria-hidden="true" />}
        </button>
      </div>

      {searchOpen && (
        <label className="relative mx-2.5 mt-2 block">
          <span className="sr-only">Search chat sessions</span>
          <Search
            size={12}
            aria-hidden="true"
            className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted"
          />
          <input
            ref={searchRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search sessions…"
            className="w-full rounded-sm border border-border bg-surface-primary py-1.5 pl-8 pr-2 text-[12px] text-text-primary outline-none placeholder:text-text-muted focus:border-border-focus"
          />
        </label>
      )}

      <div className="flex items-center px-3 pb-1 pt-3 text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">
        <span>Conversations</span>
        <span className="ml-auto font-mono font-normal tracking-normal">{filtered.length}</span>
      </div>

      <div className="flex-1 space-y-0.5 overflow-y-auto px-2 pb-3">
        {filtered.length === 0 && (
          <div className="px-3 py-7 text-center text-[12px] leading-relaxed text-text-muted">
            {sessions.length === 0
              ? "Your security conversations will appear here."
              : "No matching conversations."}
          </div>
        )}
        {filtered.map((s) => {
          const active = s.id === activeId;
          return (
            <div
              key={s.id}
              className={`group relative rounded-sm border px-2.5 py-2 transition-colors ${ active ? "border-accent-glow bg-accent-subtle" : "border-transparent hover:bg-surface-hover" }`}
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
                      className={`block truncate text-[12px] font-medium ${ active ? "text-text-primary" : "text-text-secondary" }`}
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
