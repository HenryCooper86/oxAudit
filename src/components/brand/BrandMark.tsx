import type { JSX, SVGProps } from "react";
import { useId } from "react";

const SWORD_PATH = `
  M 242 42
  L 256 18
  L 270 42
  V 326
  H 304
  L 314 350
  H 272
  V 414
  L 286 432
  L 256 466
  L 226 432
  L 240 414
  V 350
  H 198
  L 208 326
  H 242
  Z
`;

const SHIELD_PATH = `
  M 256 146
  C 278 157 302 163 326 158
  V 248
  C 326 328 301 388 256 430
  C 211 388 186 328 186 248
  V 158
  C 210 163 234 157 256 146
  Z
`;

/**
 * The oxAudit mark: two straight swords crossed behind a compact heraldic
 * shield. Monochrome (`currentColor`) so it inherits the accent or text color
 * wherever it is used, on either theme.
 */
export function BrandMark({
  className,
  ...props
}: SVGProps<SVGSVGElement>): JSX.Element {
  const maskId = `brand-sword-clearance-${useId().replace(/:/g, "")}`;

  return (
    <svg
      viewBox="0 0 512 512"
      aria-hidden="true"
      focusable="false"
      className={className}
      {...props}
    >
      <defs>
        <mask id={maskId} maskUnits="userSpaceOnUse" x="0" y="0" width="512" height="512">
          <rect width="512" height="512" fill="white" />
          <path
            fill="black"
            stroke="black"
            strokeWidth="24"
            strokeLinejoin="round"
            d={SHIELD_PATH}
          />
        </mask>
      </defs>
      <g mask={`url(#${maskId})`}>
        <path
          data-brand-layer="sword-left"
          fill="currentColor"
          transform="rotate(-45 256 256)"
          d={SWORD_PATH}
        />
        <path
          data-brand-layer="sword-right"
          fill="currentColor"
          transform="rotate(45 256 256)"
          d={SWORD_PATH}
        />
      </g>
      <path data-brand-layer="shield" fill="currentColor" d={SHIELD_PATH} />
    </svg>
  );
}
