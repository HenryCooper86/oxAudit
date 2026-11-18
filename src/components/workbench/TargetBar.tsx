import type { JSX, ReactNode } from "react";

export function TargetBar(props: {
  children: ReactNode;
  secondary?: ReactNode;
  primary: ReactNode;
}): JSX.Element {
  const { children, secondary, primary } = props;

  return (
    <section aria-label="Scan target" className="surface-card @container p-4">
      <div className="flex flex-wrap items-start gap-3">
        <div className="min-w-0 basis-full sm:min-w-[min(100%,24rem)] sm:flex-1">{children}</div>
        {/* The 20px margin drops the primary action level with the 32px field under its 20px label; the hint below no longer pulls it down. */}
        <div className="flex min-w-0 max-w-full flex-wrap items-center gap-2 @[35rem]:mt-5">{primary}</div>
      </div>
      {secondary && <div className="mt-3 border-t border-border pt-3 empty:hidden">{secondary}</div>}
    </section>
  );
}
