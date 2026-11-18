import type { JSX, ReactNode } from "react";

/**
 * oxFuzz's dashboard metric: a card with a 32px icon chip, a muted label, the
 * value, and an optional detail. `attention` switches the chip to the error
 * tint for a count that needs action. A value is a count of what was found or
 * recorded, never a verdict: callers pass "unknown" rather than 0 when a count
 * was not evaluated.
 */
export function MetricTile({
  icon,
  label,
  value,
  detail,
  attention = false,
}: {
  icon: ReactNode;
  label: string;
  value: ReactNode;
  detail?: string;
  attention?: boolean;
}): JSX.Element {
  return (
    <div className="surface-card flex items-center gap-3 p-4">
      <span
        aria-hidden="true"
        className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md ${attention ? "bg-error-subtle text-error" : "bg-accent-subtle text-accent"}`}
      >
        {icon}
      </span>
      <span className="min-w-0">
        <span className="block text-[12px] text-text-muted">{label}</span>
        <span className="text-[17px] font-semibold tabular-nums text-text-primary">{value}</span>
        {detail && <span className="ml-2 text-[12px] text-text-muted">{detail}</span>}
      </span>
    </div>
  );
}

/**
 * The summary strip: tiles in an auto-fit grid (oxFuzz's dashboard metrics).
 * A labelled region when `label` is given.
 */
export function MetricGrid({
  label,
  children,
  minTile = 190,
}: {
  label?: string;
  children: ReactNode;
  /** Narrowest tile in px before the grid wraps. */
  minTile?: number;
}): JSX.Element {
  return (
    <section
      aria-label={label}
      className="grid gap-3"
      style={{ gridTemplateColumns: `repeat(auto-fit, minmax(min(100%, ${minTile}px), 1fr))` }}
    >
      {children}
    </section>
  );
}
