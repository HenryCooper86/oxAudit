import type { JSX, SVGProps } from "react";

/**
 * The oxAudit mark: a symmetric bull-head silhouette whose horns double as a
 * shield cue for protection. Monochrome (`currentColor`) so it inherits the
 * accent or text color wherever it is used, on either theme.
 */
export function BrandMark({
  className,
  ...props
}: SVGProps<SVGSVGElement>): JSX.Element {
  return (
    <svg
      viewBox="0 0 512 512"
      aria-hidden="true"
      focusable="false"
      className={className}
      {...props}
    >
      <path
        fill="currentColor"
        fillRule="evenodd"
        d="M 168 208
           C 138 168 104 132 76 92
           C 70 150 108 200 156 244
           C 138 306 160 364 206 402
           Q 256 436 306 402
           C 352 364 374 306 356 244
           C 404 200 442 150 436 92
           C 408 132 374 168 344 208
           Q 256 186 168 208
           Z
           M 174 268 a 22 14 0 1 0 44 0 a 22 14 0 1 0 -44 0 Z
           M 294 268 a 22 14 0 1 0 44 0 a 22 14 0 1 0 -44 0 Z"
      />
    </svg>
  );
}
