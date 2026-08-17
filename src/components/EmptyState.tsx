import type { ReactNode } from "react";

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-ink-600 bg-ink-900/50 px-6 py-14 text-center">
      {icon && <div className="text-slate-600">{icon}</div>}
      <div>
        <div className="text-sm font-semibold text-slate-300">{title}</div>
        {description && (
          <div className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-slate-500">
            {description}
          </div>
        )}
      </div>
      {action && <div className="mt-1">{action}</div>}
    </div>
  );
}
