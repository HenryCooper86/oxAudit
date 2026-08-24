import { Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import {
  NAVIGATION_COMMANDS,
  filterCommands,
  groupCommands,
  moveSelection,
  type PaletteCommand,
} from "../../lib/commandPalette";
import { useAppStore } from "../../lib/stores";

/**
 * Reach any screen from the keyboard.
 *
 * oxAudit has fifteen screens, and an analyst working a backlog moves between
 * findings, the assistant, and an export several times a minute. A sidebar is
 * fine for learning the product and slow for using it.
 *
 * The palette is deliberately navigation-only for now. Adding "run a scan" or
 * "record a review" to a list where Enter fires the highlighted row means a
 * mistyped query can start work or change a decision — those belong behind
 * their own confirmation, not behind a fuzzy match.
 */
export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const setPage = useAppStore((state) => state.setPage);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const matches = useMemo(() => filterCommands(NAVIGATION_COMMANDS, query), [query]);
  const grouped = useMemo(() => groupCommands(matches), [matches]);

  // A new query is a new list; keeping the old index would leave the highlight
  // on whatever happens to be in that position now.
  useEffect(() => setSelected(0), [query]);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setSelected(0);
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const frame = requestAnimationFrame(() => inputRef.current?.focus());
    return () => {
      cancelAnimationFrame(frame);
      // Return focus where it was, so dismissing the palette leaves the
      // keyboard exactly where it started.
      if (previous?.isConnected) previous.focus();
    };
  }, [open]);

  // Keep the highlighted row in view when it moves off-screen under the keys.
  useEffect(() => {
    listRef.current
      ?.querySelector('[data-selected="true"]')
      ?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  if (!open) return null;

  const run = (command: PaletteCommand) => {
    setPage(command.page);
    onClose();
  };

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key === "ArrowDown" || (event.key === "n" && event.ctrlKey)) {
      event.preventDefault();
      setSelected((current) => moveSelection(current, 1, matches.length));
      return;
    }
    if (event.key === "ArrowUp" || (event.key === "p" && event.ctrlKey)) {
      event.preventDefault();
      setSelected((current) => moveSelection(current, -1, matches.length));
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      const command = matches[selected];
      // Enter on an empty result set does nothing rather than guessing.
      if (command) run(command);
    }
  };

  let index = -1;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 p-6 pt-[12vh]"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="w-full max-w-lg overflow-hidden rounded-md border border-border bg-surface-secondary shadow-lg"
        onKeyDown={onKeyDown}
      >
        <div className="flex items-center gap-2 border-b border-border px-3">
          <Search size={15} aria-hidden="true" className="text-text-muted" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Go to…"
            aria-label="Search commands"
            aria-controls="command-palette-results"
            aria-activedescendant={matches[selected] ? `command-${matches[selected].id}` : undefined}
            className="w-full bg-transparent py-3 text-[13px] text-text-primary outline-none placeholder:text-text-muted"
          />
        </div>

        <div
          ref={listRef}
          id="command-palette-results"
          role="listbox"
          aria-label="Commands"
          className="max-h-80 overflow-y-auto py-1"
        >
          {matches.length === 0 && (
            <p className="px-3 py-6 text-center text-[12px] text-text-muted" role="status">
              Nothing matches “{query}”.
            </p>
          )}

          {grouped.map(([group, commands]) => (
            <div key={group}>
              <div className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-text-muted">
                {group}
              </div>
              {commands.map((command) => {
                index += 1;
                const isSelected = index === selected;
                const position = index;
                return (
                  <div
                    key={command.id}
                    id={`command-${command.id}`}
                    role="option"
                    aria-selected={isSelected}
                    data-selected={isSelected}
                    onMouseMove={() => setSelected(position)}
                    onClick={() => run(command)}
                    className={`cursor-pointer px-3 py-1.5 text-[13px] ${
                      isSelected
                        ? "bg-surface-active text-text-primary"
                        : "text-text-secondary hover:bg-surface-hover"
                    }`}
                  >
                    {command.title}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
