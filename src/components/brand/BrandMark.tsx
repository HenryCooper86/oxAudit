import type { JSX, SVGProps } from "react";

export function BrandMark({
  className,
  ...props
}: SVGProps<SVGSVGElement>): JSX.Element {
  return (
    <svg
      viewBox="0 0 96 64"
      aria-hidden="true"
      focusable="false"
      className={className}
      {...props}
    >
      <path
        fill="currentColor"
        fillRule="evenodd"
        d="M31 7C16.6 7 6 17.5 6 32s10.6 25 25 25 25-10.5 25-25S45.4 7 31 7Zm0 10c8.3 0 14 6.1 14 15s-5.7 15-14 15-14-6.1-14-15 5.7-15 14-15Z"
      />
      <path
        fill="currentColor"
        d="M47 12h14l8 11 8-11h14L76 32l16 20H78L69 41 60 52H46l16-20-15-20Z"
      />
    </svg>
  );
}
