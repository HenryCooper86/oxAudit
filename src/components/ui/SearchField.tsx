import { Search } from "lucide-react";
import { forwardRef, type InputHTMLAttributes, type JSX } from "react";

/**
 * The results-toolbar search box: a 28px field with a leading magnifier. Give
 * it `aria-label` (or a visible label elsewhere); `placeholder` is only a hint.
 */
export const SearchField = forwardRef<
  HTMLInputElement,
  Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & { wrapperClassName?: string }
>(function SearchField({ className = "", wrapperClassName = "", ...props }, ref): JSX.Element {
  return (
    <span className={`relative inline-block min-w-0 ${wrapperClassName}`}>
      <Search size={13} aria-hidden="true" className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
      <input
        ref={ref}
        type="text"
        className={`h-7 w-full rounded-md border border-border bg-surface-primary pl-8 pr-2 text-[12px] text-text-primary outline-none transition-colors duration-150 placeholder:text-text-muted focus:border-border-focus disabled:cursor-not-allowed disabled:opacity-55 ${className}`}
        {...props}
      />
    </span>
  );
});
