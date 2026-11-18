import { PanelLeftClose, PanelLeftOpen } from "lucide-react";
import type { JSX } from "react";

export function PanelCollapseButton({
  controls,
  expanded,
  label,
  onToggle,
  className = "",
}: {
  controls: string;
  expanded: boolean;
  label: string;
  onToggle: () => void;
  className?: string;
}): JSX.Element {
  const action = expanded ? "Collapse" : "Expand";

  return (
    <button
      type="button"
      title={`${action} ${label}`}
      aria-label={`${action} ${label}`}
      aria-expanded={expanded}
      aria-controls={controls}
      onClick={onToggle}
      className={`inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-text-muted transition-colors hover:bg-surface-hover hover:text-text-primary ${className}`}
    >
      {expanded ? (
        <PanelLeftClose aria-hidden="true" size={15} />
      ) : (
        <PanelLeftOpen aria-hidden="true" size={15} />
      )}
    </button>
  );
}
