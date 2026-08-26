import type { JSX } from "react";
import type { SlashCommand } from "../../lib/slashCommands";

/**
 * The composer's slash-command menu. Rendered as a listbox above the composer;
 * keyboard movement is owned by the textarea, which feeds `selectedIndex` back
 * here so highlight and execution stay in step.
 */
export function SlashCommandMenu({
  commands,
  selectedIndex,
  onSelect,
  onHighlight,
}: {
  commands: SlashCommand[];
  selectedIndex: number;
  onSelect: (command: SlashCommand) => void;
  onHighlight: (index: number) => void;
}): JSX.Element | null {
  if (commands.length === 0) return null;
  const safeIndex = Math.min(Math.max(0, selectedIndex), commands.length - 1);

  return (
    <ul
      role="listbox"
      aria-label="Slash commands"
      className="mb-1 overflow-hidden rounded-md border border-border bg-surface-secondary shadow-md"
    >
      {commands.map((command, index) => {
        const selected = index === safeIndex;
        return (
          <li key={command.id} role="presentation">
            <button
              type="button"
              role="option"
              aria-selected={selected}
              onMouseEnter={() => onHighlight(index)}
              onClick={() => onSelect(command)}
              className={`flex w-full items-baseline gap-2.5 px-3 py-1.5 text-left ${
                selected ? "bg-surface-tertiary" : ""
              }`}
            >
              <span className="shrink-0 font-mono text-[12px] font-medium text-accent">
                {command.id}
              </span>
              <span className="truncate text-[12px] text-text-secondary">
                {command.description}
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}
