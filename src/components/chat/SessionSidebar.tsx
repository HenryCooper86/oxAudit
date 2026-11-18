import { useEffect, useRef, useState } from "react";
import { AlertTriangle, Check, MessageSquare, PanelRightClose, Pencil, Plus, RotateCw, Search, Trash2, X } from "lucide-react";
import { fmtDate } from "../../lib/format";
import type { SessionInfo } from "../../lib/types";

/**
 * The Assistant's Conversations panel: new chat, search, active highlight,
 * streaming dot, inline rename, two-step delete, and a load error with Retry.
 * It fills the panel dock the header's "Conversations" toggle opens.
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
  loadError = null,
  onRetry,
  onClose,
  id = "assistant-sessions-panel",
}: {
  sessions: SessionInfo[];
  activeId: string | null;
  busy: boolean;
  disabled?: boolean;
  /**
   * Why the session list could not be loaded. Shown in place of the empty
   * state, which would otherwise claim there is simply nothing saved yet.
   */
  loadError?: string | null;
  onRetry?: () => void;
  onSelect: (id: string) => void;
  onCreate: () => void;
  onRename: (id: string, title: string) => void;
  onDelete: (id: string) => void;
  /** Closes the panel; rendered as the header's close button when given. */
  onClose?: () => void;
  /** The panel's id, the target of the header toggle's `aria-controls`. */
  id?: string;
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
      id={id}
      aria-label="Chat sessions"
      className="flex h-full min-h-0 w-full flex-col bg-surface-secondary"
    >
      <div className="flex h-11 shrink-0 items-center gap-1 border-b border-border pl-4 pr-2">
        <h2 className="text-[10.5px] font-semibold uppercase tracking-[0.08em] text-text-muted">
          Conversations
        </h2>
        <span className="ml-1.5 font-mono text-[10.5px] tabular-nums text-text-muted">{filtered.length}</span>
        <span className="flex-1" />
        <button
          type="button"
          aria-label={searchOpen ? "Close session search" : "Search chat sessions"}
          aria-expanded={searchOpen}
          title={searchOpen ? "Close session search" : "Search chat sessions"}
          onClick={() => {
            setSearchOpen((open) => !open);
            if (searchOpen) setQuery("");
          }}
          className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-md transition-colors duration-150 ${searchOpen ? "bg-accent-subtle text-accent" : "text-text-muted hover:bg-surface-hover hover:text-text-primary"}`}
        >
          {searchOpen ? <X size={14} aria-hidden="true" /> : <Search size={14} aria-hidden="true" />}
        </button>
        {onClose && (
          <button
            type="button"
            aria-label="Close conversations"
            title="Close conversations"
            onClick={onClose}
            className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-text-muted transition-colors duration-150 hover:bg-surface-hover hover:text-text-primary"
          >
            <PanelRightClose size={14} aria-hidden="true" />
          </button>
        )}
      </div>

      <div className="shrink-0 px-3 pt-3">
        <button
          type="button"
          onClick={onCreate}
          disabled={controlsDisabled}
          className="flex h-8 w-full items-center gap-2 rounded-md border border-border bg-surface-primary px-2.5 text-left text-[13px] font-medium text-text-primary transition-colors duration-150 hover:border-border-strong hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-55"
        >
          <Plus size={15} aria-hidden="true" className="shrink-0 text-accent" />
          New chat
        </button>
      </div>

      <div id="assistant-session-list" className="flex min-h-0 flex-1 flex-col">
        {searchOpen && (
          <label className="relative mx-3 mt-2 block">
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
              className="h-8 w-full rounded-md border border-border bg-surface-primary pl-8 pr-2 text-[12px] text-text-primary outline-none placeholder:text-text-muted focus:border-border-focus"
            />
          </label>
        )}

        <div className="mt-2 flex-1 space-y-0.5 overflow-y-auto px-3 pb-3">
          {loadError && (
            <div
              role="alert"
              className="surface-card mb-1 border-l-[3px] border-l-error px-3 py-2.5 text-[12px] leading-relaxed shadow-none"
            >
              <p className="flex items-center gap-1.5 font-medium text-error">
                <AlertTriangle size={12} aria-hidden="true" className="shrink-0" />
                Conversations could not be loaded.
              </p>
              <p className="mt-0.5 break-words text-text-secondary">{loadError}</p>
              {onRetry && (
                <button
                  type="button"
                  onClick={onRetry}
                  disabled={disabled}
                  className="mt-2 inline-flex h-7 items-center gap-1.5 rounded-md border border-border bg-surface-primary px-2.5 text-[11px] font-medium text-text-primary transition-colors hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-55"
                >
                  <RotateCw size={11} aria-hidden="true" />
                  Retry
                </button>
              )}
            </div>
          )}
          {filtered.length === 0 && !loadError && (
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
              className={`group relative rounded-md border px-2.5 py-2 transition-colors duration-150 ${ active ? "border-border bg-surface-active" : "border-transparent hover:bg-accent-subtle" }`}
            >
              {renamingId === s.id ? (
                <div className="flex items-center gap-1">
                  <input
                    // The user just chose Rename; the field they asked for takes focus.
                    // eslint-disable-next-line jsx-a11y/no-autofocus
                    autoFocus
                    aria-label={`Rename ${s.title}`}
                    value={renameValue}
                    onChange={(e) => setRenameValue(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") commitRename();
                      if (e.key === "Escape") setRenamingId(null);
                    }}
                    className="min-w-0 flex-1 rounded-md border border-border-focus bg-surface-primary px-1.5 py-0.5 text-[13px] text-text-primary outline-none"
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
                    className="rounded-md bg-transparent px-1.5 py-0.5 text-error hover:bg-error-subtle"
                  >
                    Yes
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmDeleteId(null)}
                    className="rounded-md bg-surface-tertiary px-1.5 py-0.5 text-text-muted hover:text-text-primary"
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
                      className="mt-1 h-1.5 w-1.5 shrink-0 animate-status-pulse rounded-full bg-accent"
                    />
                  )}
                </button>
              )}

              {!controlsDisabled && renamingId !== s.id && confirmDeleteId !== s.id && (
                <div className="absolute right-1.5 top-1.5 hidden items-center gap-1 group-hover:flex group-focus-within:flex">
                  <button
                    type="button"
                    aria-label={`Rename ${s.title}`}
                    onClick={() => setRenamingId(s.id)}
                    className="rounded-md bg-surface-tertiary p-1 text-text-muted hover:text-text-primary"
                    title="Rename"
                  >
                    <Pencil size={11} aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    aria-label={`Delete ${s.title}`}
                    onClick={() => setConfirmDeleteId(s.id)}
                    className="rounded-md bg-surface-tertiary p-1 text-text-muted hover:text-error"
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
      </div>
    </aside>
  );
}
