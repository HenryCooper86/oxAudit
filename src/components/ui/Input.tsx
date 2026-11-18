import { forwardRef, type InputHTMLAttributes, type TextareaHTMLAttributes } from "react";

/**
 * Shared field chrome, after oxFuzz's Input: full-width, 8px control radius,
 * primary surface, stronger border on focus. Enabled editable fields take the
 * `--control-border` colour from the global stylesheet (3:1 against every
 * surface), which is brighter than oxFuzz's hairline on purpose.
 */
export const fieldClassName =
  "min-h-9 w-full rounded-md border border-border bg-surface-primary px-3 py-1.5 text-[13px] " +
  "text-text-primary outline-none transition-colors duration-150 placeholder:text-text-muted " +
  "focus:border-border-focus disabled:cursor-not-allowed disabled:opacity-55";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className = "", ...props }, ref) {
    return <input ref={ref} className={`${fieldClassName} ${className}`} {...props} />;
  },
);

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  TextareaHTMLAttributes<HTMLTextAreaElement>
>(function Textarea({ className = "", ...props }, ref) {
  return <textarea ref={ref} className={`${fieldClassName} ${className}`} {...props} />;
});
