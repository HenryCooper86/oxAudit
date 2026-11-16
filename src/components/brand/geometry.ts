/** Shared geometry for the React mark and generated standalone SVG masters. */

export interface BrandLayer {
  layer: string;
  d: string;
  transform?: string;
}

/**
 * The mark: a scan frame. Four corner brackets frame the thing under audit,
 * a beam crosses it, and the dot is what the scan found. Every shape is a
 * closed filled path, so one fill per layer renders identically in React,
 * rsvg, and the native icon rasterizers.
 */
export const BRAND_PATHS: readonly BrandLayer[] = [
  {
    layer: "frame-top-left",
    d: "M 118 193 L 118 130 A 12 12 0 0 1 130 118 L 193 118 A 12 12 0 0 1 193 142 L 142 142 L 142 193 A 12 12 0 0 1 118 193 Z",
  },
  {
    layer: "frame-top-right",
    d: "M 394 193 L 394 130 A 12 12 0 0 0 382 118 L 319 118 A 12 12 0 0 0 319 142 L 370 142 L 370 193 A 12 12 0 0 0 394 193 Z",
  },
  {
    layer: "frame-bottom-right",
    d: "M 394 319 L 394 382 A 12 12 0 0 1 382 394 L 319 394 A 12 12 0 0 1 319 370 L 370 370 L 370 319 A 12 12 0 0 1 394 319 Z",
  },
  {
    layer: "frame-bottom-left",
    d: "M 118 319 L 118 382 A 12 12 0 0 0 130 394 L 193 394 A 12 12 0 0 0 193 370 L 142 370 L 142 319 A 12 12 0 0 0 118 319 Z",
  },
  {
    layer: "beam",
    d: "M 95 244 L 417 244 A 12 12 0 0 1 417 268 L 95 268 A 12 12 0 0 1 95 244 Z",
  },
  {
    layer: "target",
    d: "M 256 256 m -43 0 a 43 43 0 1 0 86 0 a 43 43 0 1 0 -86 0 Z",
  },
] as const;

export const BRAND_GOLD = "#C8B560";
export const BRAND_GRAPHITE = "#151719";
