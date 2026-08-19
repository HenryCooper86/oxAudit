import { forwardRef, type InputHTMLAttributes, type TextareaHTMLAttributes } from "react";

/**
 * Shared field chrome: full-width, 4px control radius, subtle border, accent
 * on focus. Sizing matches the fields already in use across Settings and the
 * scan pages so adopting this primitive is a refactor, not a redesign.
 */
export const fieldClassName =
  "w-full rounded-sm border border-border bg-surface-primary px-3 py-2 text-[13px] " +
  "text-text-primary outline-none transition-colors placeholder:text-text-muted " +
  "focus:border-accent disabled:cursor-not-allowed disabled:opacity-55";

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
