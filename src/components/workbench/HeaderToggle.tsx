import type { JSX, ReactNode } from "react";

/**
 * oxFuzz's header toggle: a 32px icon button on the 8px control radius,
 * muted at rest, accent on accent-subtle while pressed. `pressed` undefined
 * renders a plain action button (no `aria-pressed`).
 */
export function HeaderToggle({
  label,
  pressed,
  onClick,
  children,
  controls,
  expanded,
  keyShortcuts,
  disabled,
  id,
}: {
  label: string;
  pressed?: boolean;
  onClick: () => void;
  children: ReactNode;
  controls?: string;
  expanded?: boolean;
  keyShortcuts?: string;
  disabled?: boolean;
  id?: string;
}): JSX.Element {
  return (
    <button
      id={id}
      type="button"
      title={label}
      aria-label={label}
      aria-pressed={pressed}
      aria-expanded={expanded}
      aria-controls={controls}
      aria-keyshortcuts={keyShortcuts}
      disabled={disabled}
      onClick={onClick}
      className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md transition-colors duration-150 disabled:pointer-events-none disabled:opacity-55 ${
        pressed ? "bg-accent-subtle text-accent" : "text-text-muted hover:bg-surface-hover hover:text-text-primary"
      }`}
    >
      {children}
    </button>
  );
}
