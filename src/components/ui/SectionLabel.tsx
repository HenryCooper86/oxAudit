import type { JSX, ReactNode } from "react";

/** oxFuzz's uppercase section label (sidebar groups, panel toolbars). */
export function SectionLabel({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}): JSX.Element {
  return (
    <span
      className={`text-[10.5px] font-semibold uppercase tracking-[0.08em] text-text-muted ${className}`}
    >
      {children}
    </span>
  );
}
