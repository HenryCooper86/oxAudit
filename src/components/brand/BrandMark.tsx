import type { JSX, SVGProps } from "react";
import { BRAND_PATHS } from "./geometry";

/** A scan frame: four corner brackets, a beam and the finding it lands on, in the current theme color. */
export function BrandMark({ className, ...props }: SVGProps<SVGSVGElement>): JSX.Element {
  return (
    <svg viewBox="0 0 512 512" aria-hidden="true" focusable="false" className={className} {...props}>
      {BRAND_PATHS.map(({ layer, d, transform }) => (
        <path key={layer} data-brand-layer={layer} fill="currentColor" d={d} transform={transform} />
      ))}
    </svg>
  );
}
