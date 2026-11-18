import { ChevronDown } from "lucide-react";
import { forwardRef, type SelectHTMLAttributes } from "react";
import { fieldClassName } from "./Input";

/**
 * `field` matches the form fields in Settings (36px); `compact` is the shorter
 * (28px), auto-width control used in results toolbars, where several sit side
 * by side.
 */
export type SelectVariant = "field" | "compact";

interface SelectProps
  extends Omit<SelectHTMLAttributes<HTMLSelectElement>, "size"> {
  variant?: SelectVariant;
}

/**
 * A native `<select>` (keyboard, screen-reader and touch behaviour untouched)
 * with the system arrow replaced by a 14px chevron, after oxFuzz's select
 * trigger. The chevron needs a wrapper, so the layout utilities a caller
 * passes (margin, width, display, flex/grid placement) move to that wrapper
 * and the select fills it; every other class stays on the control.
 */
const LAYOUT_CLASS =
  /^(?:[^\s:]+:)*-?(?:m[trblxyse]?-|w-|min-w-|max-w-|flex$|flex-|grow|shrink|basis-|self-|justify-self-|col-|row-|order-|block$|inline|hidden$)/;
const WIDTH_CLASS = /^(?:[^\s:]+:)*(?:w-|flex-1|basis-)/;
const DISPLAY_CLASS = /^(?:[^\s:]+:)*(?:block|inline|flex$|hidden)/;

const BASE =
  "appearance-none cursor-pointer pr-8 [background-image:none] " +
  "disabled:cursor-not-allowed";
const FIELD = `${fieldClassName} h-9 ${BASE}`;
const COMPACT =
  "h-7 w-full rounded-md border border-border bg-surface-primary pl-2.5 text-[12px] " +
  "text-text-secondary outline-none transition-colors duration-150 " +
  "focus:border-border-focus disabled:opacity-55 " +
  BASE;

export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { variant = "field", className = "", children, ...props },
  ref,
) {
  const tokens = className.split(/\s+/).filter(Boolean);
  const layout = tokens.filter((token) => LAYOUT_CLASS.test(token));
  const rest = tokens.filter((token) => !LAYOUT_CLASS.test(token));
  const field = variant === "field";
  const hasWidth = layout.some((token) => WIDTH_CLASS.test(token));
  const hasDisplay = layout.some((token) => DISPLAY_CLASS.test(token));
  const wrapper = [
    "relative min-w-0",
    hasDisplay ? "" : field ? "flex" : "inline-flex",
    field && !hasWidth ? "w-full" : "",
    ...layout,
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <span className={wrapper}>
      <select
        ref={ref}
        className={`${field ? FIELD : COMPACT} ${rest.join(" ")}`}
        {...props}
      >
        {children}
      </select>
      <ChevronDown
        size={14}
        aria-hidden="true"
        className={`pointer-events-none absolute top-1/2 -translate-y-1/2 text-text-muted opacity-70 ${field ? "right-3" : "right-2"}`}
      />
    </span>
  );
});
