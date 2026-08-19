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

export function ToolLaunchCard(props: ToolLaunchCardProps): JSX.Element {
  const { category, title, description, actionLabel, icon, onOpen } = props;

  return (
    <button
      type="button"
      onClick={onOpen}
      className="group flex min-h-[108px] w-full flex-col items-start rounded-sm border border-border bg-surface-secondary px-4 py-3.5 text-left transition-colors hover:border-border-strong hover:bg-surface-hover"
    >
      <div className="flex w-full items-center justify-between gap-3">
        <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-accent">
          {category}
        </span>
        <span className="text-text-muted" aria-hidden="true">
          {icon}
        </span>
      </div>
      <span className="mt-2 text-[14px] font-semibold text-text-primary">{title}</span>
      <span className="mt-1 text-[13px] leading-5 text-text-muted">{description}</span>
      <span className="mt-auto inline-flex items-center gap-1 pt-3 text-[13px] font-medium text-accent">
        {actionLabel}
        <ArrowUpRight size={14} strokeWidth={1.8} aria-hidden="true" />
      </span>
    </button>
  );
}
