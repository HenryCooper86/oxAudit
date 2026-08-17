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
    <aside className="flex w-60 shrink-0 flex-col border-r border-ink-800 bg-ink-900/60">
      <div className="p-3">
        <button
          onClick={onCreate}
          disabled={busy}
          className="flex w-full items-center justify-center gap-1.5 rounded-lg bg-gradient-to-r from-teal-500 to-emerald-500 px-3 py-2 text-xs font-bold text-ink-950 shadow-lg shadow-teal-900/30 hover:opacity-90 disabled:opacity-40"
        >
          <Plus size={14} /> New chat
        </button>
        <div className="relative mt-2">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-600" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search sessions…"
            className="w-full rounded-lg border border-ink-600 bg-ink-900 py-1.5 pl-8 pr-2 text-[11px] text-slate-300 outline-none placeholder:text-slate-600 focus:border-teal-500/60"
          />
        </div>
      </div>

      <div className="flex-1 space-y-0.5 overflow-y-auto px-2 pb-3">
        {filtered.length === 0 && (
          <div className="px-3 py-6 text-center text-[11px] text-slate-600">
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
                    value={renameValue}
                    onChange={(e) => setRenameValue(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") commitRename();
                      if (e.key === "Escape") setRenamingId(null);
                    }}
                    className="min-w-0 flex-1 rounded border border-teal-500/60 bg-ink-900 px-1.5 py-0.5 text-[11px] text-slate-200 outline-none"
                  />
                  <button onClick={commitRename} className="text-emerald-400">
                    <Check size={12} />
                  </button>
                  <button onClick={() => setRenamingId(null)} className="text-slate-500">
                    <X size={12} />
                  </button>
                </div>
              ) : confirmDeleteId === s.id ? (
                <div className="flex items-center gap-1.5 text-[10px]">
                  <span className="text-slate-500">Delete?</span>
                  <button
                    onClick={() => {
                      onDelete(s.id);
                      setConfirmDeleteId(null);
                    }}
                    className="rounded bg-red-500/15 px-1.5 py-0.5 text-red-300 hover:bg-red-500/25"
                  >
                    Yes
                  </button>
                  <button
                    onClick={() => setConfirmDeleteId(null)}
                    className="rounded bg-ink-800 px-1.5 py-0.5 text-slate-400 hover:text-slate-200"
                  >
                    No
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => !busy && onSelect(s.id)}
                  disabled={busy}
                  className="flex w-full items-start gap-2 text-left disabled:cursor-default"
                >
                  <MessageSquare
                    size={12}
                    className={`mt-0.5 shrink-0 ${active ? "text-teal-400" : "text-slate-600"}`}
                  />
                  <span className="min-w-0 flex-1">
                    <span
                      className={`block truncate text-[11.5px] font-medium ${
                        active ? "text-slate-100" : "text-slate-400"
                      }`}
                    >
                      {s.title}
                    </span>
                    <span className="block text-[9.5px] text-slate-600">
                      {fmtDate(s.updatedAt)}
                      {s.messageCount > 0 ? ` · ${s.messageCount} msg` : ""}
                    </span>
                  </span>
                  {active && busy && (
                    <span className="mt-1 h-1.5 w-1.5 shrink-0 animate-pulse rounded-full bg-teal-400" />
                  )}
                </button>
              )}

              {!busy && renamingId !== s.id && confirmDeleteId !== s.id && (
                <div className="absolute right-1.5 top-1.5 hidden items-center gap-0.5 group-hover:flex">
                  <button
                    onClick={() => setRenamingId(s.id)}
                    className="rounded bg-ink-800 p-0.5 text-slate-500 hover:text-slate-200"
                    title="Rename"
                  >
                    <Pencil size={11} />
                  </button>
                  <button
                    onClick={() => setConfirmDeleteId(s.id)}
                    className="rounded bg-ink-800 p-0.5 text-slate-500 hover:text-red-300"
                    title="Delete"
                  >
                    <Trash2 size={11} />
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
