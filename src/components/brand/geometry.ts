/** Shared geometry for the React mark and generated standalone SVG masters. */

export interface BrandLayer {
  layer: string;
  d: string;
  transform?: string;
}

/**
 * The mark: a magnifier whose lens holds an x. The lens is the O of oxAudit
 * and the act of auditing; the x is the x of the name. Every shape is a
 * closed filled path (the lens is an annulus with counter-wound inner
 * circle), so one fill per layer renders identically in React, rsvg, and
 * the native icon rasterizers.
 */
export const BRAND_PATHS: readonly BrandLayer[] = [
  {
    layer: "lens",
    d: "M 232 226 m -146 0 a 146 146 0 1 0 292 0 a 146 146 0 1 0 -292 0 Z M 232 226 m -90 0 a 90 90 0 1 1 180 0 a 90 90 0 1 1 -180 0 Z",
  },
  {
    layer: "handle",
    d: "M 297.49 332.51 L 381.49 416.51 A 29 29 0 0 0 422.51 375.49 L 338.51 291.49 A 29 29 0 0 0 297.49 332.51 Z",
  },
  {
    layer: "cross-first",
    d: "M 172.56 193.44 L 264.56 285.44 A 19 19 0 0 0 291.44 258.56 L 199.44 166.56 A 19 19 0 0 0 172.56 193.44 Z",
  },
  {
    layer: "cross-second",
    d: "M 264.56 166.56 L 172.56 258.56 A 19 19 0 0 0 199.44 285.44 L 291.44 193.44 A 19 19 0 0 0 264.56 166.56 Z",
  },
] as const;

export const BRAND_GOLD = "#C8B560";
export const BRAND_GRAPHITE = "#151719";
