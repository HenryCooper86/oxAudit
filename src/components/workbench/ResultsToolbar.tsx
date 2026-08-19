import type { JSX, ReactNode } from "react";

export function ResultsToolbar(props: {
  countLabel: string;
  filters?: ReactNode;
  search?: ReactNode;
  actions?: ReactNode;
}): JSX.Element {
  const { countLabel, filters, search, actions } = props;

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border bg-surface-secondary px-3 py-2.5">
      <span className="mr-1 text-[12px] font-medium tabular-nums text-text-secondary">{countLabel}</span>
      {filters && <div className="flex flex-wrap items-center gap-2">{filters}</div>}
      {(search || actions) && (
        <div className="ml-auto flex min-w-0 flex-wrap items-center justify-end gap-2">
          {search}
          {actions}
        </div>
      )}
    </div>
  );
}
