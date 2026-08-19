import { forwardRef, type ButtonHTMLAttributes } from "react";

/**
 * Variant/size vocabulary follows y-agent's `y-gui/src/components/ui/Button.tsx`.
 *
 * Two deviations, both because oxAudit's controls carry more semantic weight
 * than an agent shell's:
 *   - `danger` is tinted rather than solid. Destructive actions here sit inside
 *     dense result tables, where a solid red block would outshout the severity
 *     badges that are the actual signal.
 *   - `accent` is new: the subtle-tinted affordance used by "Ask AI" and other
 *     hand-offs into the assistant.
 */
export type ButtonVariant =
  | "primary"
  | "accent"
  | "ghost"
  | "danger"
  | "warning"
  | "outline"
  | "icon";
export type ButtonSize = "sm" | "md";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const VARIANT: Record<ButtonVariant, string> = {
  primary: "border-transparent bg-accent text-accent-contrast hover:bg-accent-hover",
  accent: "border-accent-glow bg-accent-subtle text-accent hover:bg-accent-glow",
  ghost:
    "border-border bg-transparent text-text-secondary hover:bg-surface-hover hover:text-text-primary",
  danger:
    "border-error-border bg-transparent text-error hover:bg-error-subtle",
  warning:
    "border-warning-border bg-transparent text-warning hover:bg-warning-subtle",
  outline:
    "border-border bg-surface-tertiary text-text-primary hover:border-border-strong hover:bg-surface-active",
  icon: "border-transparent bg-transparent text-text-muted hover:border-border hover:bg-surface-hover hover:text-text-primary",
};

const SIZE: Record<ButtonSize, string> = {
  sm: "h-7 px-2.5 text-[11px]",
  md: "h-8 px-3 text-[12px]",
};

const ICON_SIZE: Record<ButtonSize, string> = {
  sm: "h-7 w-7",
  md: "h-8 w-8",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "ghost", size = "md", className = "", type = "button", ...props },
  ref,
) {
  const sizing = variant === "icon" ? ICON_SIZE[size] : SIZE[size];

  return (
    <button
      ref={ref}
      type={type}
      className={[
        "inline-flex shrink-0 items-center justify-center gap-1.5",
        "cursor-pointer font-sans font-medium whitespace-nowrap",
        "rounded-sm border border-solid transition-colors duration-150",
        "disabled:pointer-events-none disabled:opacity-55",
        VARIANT[variant],
        sizing,
        className,
      ].join(" ")}
      {...props}
    />
  );
});
