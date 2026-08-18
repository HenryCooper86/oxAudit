import type { JSX, ReactNode } from "react";

export function TargetBar(props: {
  children: ReactNode;
  secondary?: ReactNode;
  primary: ReactNode;
}): JSX.Element {
  const { children, secondary, primary } = props;

  return (
    <section aria-label="Scan target" className="rounded-lg border border-ink-700 bg-ink-850 p-4">
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-[min(100%,24rem)] flex-1">{children}</div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">{primary}</div>
      </div>
      {secondary && <div className="mt-3 border-t border-ink-800 pt-3">{secondary}</div>}
    </section>
  );
}
