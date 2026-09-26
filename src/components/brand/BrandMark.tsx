import type { JSX, SVGProps } from "react";
import { BRAND_PATHS } from "./geometry";

/** A magnifier whose lens holds an x — the o and x of oxAudit — in the current theme color. */
export function BrandMark({ className, ...props }: SVGProps<SVGSVGElement>): JSX.Element {
  return (
    <svg viewBox="0 0 512 512" aria-hidden="true" focusable="false" className={className} {...props}>
      {BRAND_PATHS.map(({ layer, d, transform }) => (
        <path key={layer} data-brand-layer={layer} fill="currentColor" d={d} transform={transform} />
      ))}
    </svg>
  );
}
