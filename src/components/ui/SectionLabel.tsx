import type { JSX, ReactNode } from "react";

/** 10px uppercase label used for sidebar sections and panel toolbars. */
export function SectionLabel({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}): JSX.Element {
  return (
    <span
      className={`text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted ${className}`}
    >
      {children}
    </span>
  );
}
