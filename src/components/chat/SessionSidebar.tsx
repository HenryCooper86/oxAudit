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
  onSelect,
  onCreate,
  onRename,
  onDelete,
}: {
  sessions: SessionInfo[];
  activeId: string | null;
  busy: boolean;
  onSelect: (id: string) => void;
  onCreate: () => void;
  onRename: (id: string, title: string) => void;
  onDelete: (id: string) => void;
}) {
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
      className="flex w-60 shrink-0 flex-col border-r border-ink-800 bg-ink-900/60"
    >
      <div className="p-3">
        <button
          type="button"
          onClick={onCreate}
          disabled={busy}
          className="flex w-full items-center justify-center gap-1.5 rounded-md bg-accent-500 px-3 py-2 text-[12px] font-semibold text-ink-950 hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Plus size={14} aria-hidden="true" /> New chat
        </button>
        <label className="relative mt-2 block">
          <span className="sr-only">Search chat sessions</span>
          <Search
            size={12}
            aria-hidden="true"
            className="absolute left-2.5 top-1/2 -translate-y-1/2 text-stone-500"
          />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search sessions…"
            className="w-full rounded-md border border-ink-600 bg-ink-950 py-1.5 pl-8 pr-2 text-[13px] text-stone-200 outline-none placeholder:text-stone-400 focus:border-accent-500/70"
          />
        </label>
      </div>

      <div className="flex-1 space-y-0.5 overflow-y-auto px-2 pb-3">
        {filtered.length === 0 && (
          <div className="px-3 py-6 text-center text-[12px] text-stone-400">
            {sessions.length === 0 ? "No chats yet" : "No matches"}
          </div>
        )}
        {filtered.map((s) => {
          const active = s.id === activeId;
          return (
            <div
              key={s.id}
              className={`group relative rounded-lg px-2.5 py-2 transition-colors ${
                active ? "bg-ink-750" : "hover:bg-ink-850"
              }`}
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
                    className="min-w-0 flex-1 rounded border border-accent-500/60 bg-ink-950 px-1.5 py-0.5 text-[13px] text-stone-200 outline-none"
                  />
                  <button
                    type="button"
                    aria-label="Save session name"
                    onClick={commitRename}
                    className="text-emerald-400"
                  >
                    <Check size={12} aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    aria-label="Cancel session rename"
                    onClick={() => setRenamingId(null)}
                    className="text-stone-400"
                  >
                    <X size={12} aria-hidden="true" />
                  </button>
                </div>
              ) : confirmDeleteId === s.id ? (
                <div className="flex items-center gap-1.5 text-[12px]">
                  <span className="text-stone-400">Delete?</span>
                  <button
                    type="button"
                    onClick={() => {
                      onDelete(s.id);
                      setConfirmDeleteId(null);
                    }}
                    className="rounded bg-red-500/15 px-1.5 py-0.5 text-red-300 hover:bg-red-500/25"
                  >
                    Yes
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmDeleteId(null)}
                    className="rounded bg-ink-800 px-1.5 py-0.5 text-stone-400 hover:text-stone-200"
                  >
                    No
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={() => !busy && onSelect(s.id)}
                  disabled={busy}
                  aria-current={active ? "true" : undefined}
                  className="flex w-full items-start gap-2 text-left disabled:cursor-default"
                >
                  <MessageSquare
                    size={12}
                    aria-hidden="true"
                    className={`mt-0.5 shrink-0 ${active ? "text-accent-400" : "text-stone-600"}`}
                  />
                  <span className="min-w-0 flex-1">
                    <span
                      className={`block truncate text-[12px] font-medium ${
                        active ? "text-stone-100" : "text-stone-400"
                      }`}
                    >
                      {s.title}
                    </span>
                    <span className="block text-[11px] text-stone-400">
                      {fmtDate(s.updatedAt)}
                      {s.messageCount > 0 ? ` · ${s.messageCount} msg` : ""}
                    </span>
                  </span>
                  {active && busy && (
                    <span
                      role="status"
                      aria-label="Assistant is responding"
                      className="mt-1 h-1.5 w-1.5 shrink-0 animate-pulse rounded-full bg-accent-400"
                    />
                  )}
                </button>
              )}

              {!busy && renamingId !== s.id && confirmDeleteId !== s.id && (
                <div className="absolute right-1.5 top-1.5 hidden items-center gap-0.5 group-hover:flex group-focus-within:flex">
                  <button
                    type="button"
                    aria-label={`Rename ${s.title}`}
                    onClick={() => setRenamingId(s.id)}
                    className="rounded bg-ink-800 p-0.5 text-stone-400 hover:text-stone-100"
                    title="Rename"
                  >
                    <Pencil size={11} aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    aria-label={`Delete ${s.title}`}
                    onClick={() => setConfirmDeleteId(s.id)}
                    className="rounded bg-ink-800 p-0.5 text-stone-400 hover:text-red-300"
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
