import type { ReactNode } from "react";

export function TopBar({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <header className="flex items-center justify-between gap-4 px-6 pb-3 pt-5">
      <div className="min-w-0">
        <h1 className="truncate text-[15px] font-bold tracking-tight text-slate-100">{title}</h1>
        {subtitle && <p className="truncate text-[11px] text-slate-500">{subtitle}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </header>
  );
}
