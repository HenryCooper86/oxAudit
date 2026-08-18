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
      className="group flex min-h-[108px] w-full flex-col items-start rounded-lg border border-ink-700 bg-ink-850 px-4 py-3.5 text-left transition-colors hover:border-ink-600 hover:bg-ink-800"
    >
      <div className="flex w-full items-center justify-between gap-3">
        <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-accent-400">
          {category}
        </span>
        <span className="text-slate-400" aria-hidden="true">
          {icon}
        </span>
      </div>
      <span className="mt-2 text-[14px] font-semibold text-slate-100">{title}</span>
      <span className="mt-1 text-[13px] leading-5 text-slate-400">{description}</span>
      <span className="mt-auto inline-flex items-center gap-1 pt-3 text-[13px] font-medium text-accent-400">
        {actionLabel}
        <ArrowUpRight size={14} strokeWidth={1.8} aria-hidden="true" />
      </span>
    </button>
  );
}
