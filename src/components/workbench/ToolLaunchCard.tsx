import { ArrowUpRight } from "lucide-react";
import type { JSX, ReactNode } from "react";

interface ToolLaunchCardProps {
  category: "Scanning" | "Research";
  title: string;
  description: string;
  actionLabel: string;
  icon: ReactNode;
  onOpen: () => void;
}

/**
 * A launcher card on the Dashboard: a `surface-card` button with oxFuzz's
 * metric-tile icon chip (32px, accent on accent-subtle), the tool's name and
 * purpose, and its action. Hover lifts the surface and firms the border.
 */
export function ToolLaunchCard(props: ToolLaunchCardProps): JSX.Element {
  const { category, title, description, actionLabel, icon, onOpen } = props;

  return (
    <button
      type="button"
      onClick={onOpen}
      className="surface-card group flex min-h-[124px] w-full flex-col items-start p-4 text-left transition-colors duration-150 hover:border-border-focus hover:bg-surface-hover"
    >
      <div className="flex w-full items-center gap-3">
        <span
          aria-hidden="true"
          className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-accent-subtle text-accent"
        >
          {icon}
        </span>
        <span className="min-w-0">
          <span className="block text-[10.5px] font-semibold uppercase tracking-[0.08em] text-text-muted">
            {category}
          </span>
          <span className="block text-[14px] font-semibold text-text-primary">{title}</span>
        </span>
      </div>
      <span className="mt-2 text-[13px] leading-5 text-text-secondary">{description}</span>
      <span className="mt-auto inline-flex items-center gap-1 pt-3 text-[12px] font-medium text-accent">
        {actionLabel}
        <ArrowUpRight size={14} strokeWidth={1.8} aria-hidden="true" />
      </span>
    </button>
  );
}
