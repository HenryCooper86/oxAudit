import type { JSX, SVGProps } from "react";

/**
 * The oxAudit mark: a compact Spartan helmet and plume, with the helmet dome
 * doubling as a shield cue. Monochrome (`currentColor`) so it inherits the
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
        d="M 208 42
           C 251 26 307 29 356 51
           C 326 59 296 75 269 96
           H 208
           Z
           M 256 92
           C 174 92 116 155 116 241
           V 274
           H 163
           L 184 430
           H 223
           L 256 376
           L 289 430
           H 328
           L 349 274
           H 396
           V 241
           C 396 155 338 92 256 92
           Z
           M 163 222
           C 184 172 218 146 256 146
           C 294 146 328 172 349 222
           L 340 270
           H 280
           V 351
           L 256 330
           L 232 351
           V 270
           H 172
           Z"
      />
    </svg>
  );
}
