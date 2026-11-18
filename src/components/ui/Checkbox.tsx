import { forwardRef, type InputHTMLAttributes, type JSX, type ReactNode } from "react";

/**
 * A labelled native checkbox on the control scale: 16px box, accent when
 * checked, the label to its right. The input keeps its `checkbox` role and the
 * label text as its accessible name; pass `aria-label` instead of `children`
 * when the label is shown elsewhere.
 */
export const Checkbox = forwardRef<
  HTMLInputElement,
  Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & { children?: ReactNode; labelClassName?: string }
>(function Checkbox({ children, className = "", labelClassName = "", disabled, ...props }, ref): JSX.Element {
  return (
    <label
      className={`inline-flex items-center gap-2 text-[12px] text-text-secondary ${disabled ? "cursor-not-allowed opacity-55" : "cursor-pointer"} ${labelClassName}`}
    >
      <input
        ref={ref}
        type="checkbox"
        disabled={disabled}
        className={`h-4 w-4 shrink-0 cursor-[inherit] rounded-sm accent-[var(--accent)] ${className}`}
        {...props}
      />
      {children}
    </label>
  );
});
