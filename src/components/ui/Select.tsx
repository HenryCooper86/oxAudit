import { forwardRef, type SelectHTMLAttributes } from "react";
import { fieldClassName } from "./Input";

/**
 * `field` matches the form fields in Settings; `compact` is the shorter,
 * auto-width control used in results toolbars, where several sit side by side.
 */
export type SelectVariant = "field" | "compact";

interface SelectProps
  extends Omit<SelectHTMLAttributes<HTMLSelectElement>, "size"> {
  variant?: SelectVariant;
}

const COMPACT =
  "rounded-sm border border-border bg-surface-secondary px-2 py-1.5 text-[12px] " +
  "text-text-secondary outline-none transition-colors focus:border-accent " +
  "disabled:cursor-not-allowed disabled:opacity-55";

export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { variant = "field", className = "", children, ...props },
  ref,
) {
  const base = variant === "compact" ? COMPACT : fieldClassName;
  return (
    <select ref={ref} className={`${base} cursor-pointer ${className}`} {...props}>
      {children}
    </select>
  );
});
