import { ListChecks, Sparkles, type LucideIcon } from "lucide-react";
import type { JSX } from "react";
import type { ChatMode } from "../../lib/assistantComposer";

const MODES: ReadonlyArray<{ mode: ChatMode; label: string; title: string; icon: LucideIcon }> = [
  { mode: "auto", label: "Auto", title: "Auto: send the message as typed", icon: Sparkles },
  {
    mode: "plan",
    label: "Plan & act",
    title: "Plan & act: the assistant outlines a numbered plan, then acts. Not a read-only mode; tools still ask for approval.",
    icon: ListChecks,
  },
];

/** oxFuzz's composer mode toggle: two pills on an active-surface track. */
export function ComposerModeToggle({
  mode,
  onChange,
}: {
  mode: ChatMode;
  onChange: (mode: ChatMode) => void;
}): JSX.Element {
  return (
    <div role="group" aria-label="Composer mode" className="inline-flex items-center rounded-md bg-surface-active p-0.5">
      {MODES.map(({ mode: value, label, title, icon: Icon }) => {
        const active = mode === value;
        return (
          <button
            key={value}
            type="button"
            aria-pressed={active}
            title={title}
            onClick={() => onChange(value)}
            className={
              active
                ? "inline-flex h-6 items-center gap-1 whitespace-nowrap rounded-md bg-accent-subtle px-2 text-[11px] font-medium text-accent"
                : "inline-flex h-6 items-center gap-1 whitespace-nowrap rounded-md px-2 text-[11px] font-medium text-text-muted transition-colors duration-150 hover:text-text-secondary"
            }
          >
            <Icon size={12} aria-hidden="true" />
            {label}
          </button>
        );
      })}
    </div>
  );
}
