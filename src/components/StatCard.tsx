import type { ReactNode } from "react";

export function StatCard({
  label,
  value,
  icon,
  tone = "default",
  onClick,
}: {
  label: string;
  value: ReactNode;
  icon?: ReactNode;
  tone?: "default" | "danger" | "warning" | "success" | "accent";
  onClick?: () => void;
}) {
  const tones: Record<string, string> = {
    default: "text-slate-200",
    danger: "text-red-400",
    warning: "text-orange-400",
    success: "text-emerald-400",
    accent: "text-teal-300",
  };
  return (
    <button
      onClick={onClick}
      className={`flex flex-col gap-1 rounded-xl border border-ink-700 bg-ink-850 px-4 py-3 text-left transition-colors ${
        onClick ? "cursor-pointer hover:border-ink-600 hover:bg-ink-800" : "cursor-default"
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
          {label}
        </span>
        {icon && <span className="text-slate-500">{icon}</span>}
      </div>
      <div className={`text-2xl font-bold tabular-nums ${tones[tone]}`}>{value}</div>
    </button>
  );
}
