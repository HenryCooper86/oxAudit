/** Shared geometry for the React mark and generated standalone SVG masters. */
const HORN = "M 126 88 H 164 Q 168 88 168 92 V 110 Q 168 114 165 117 L 130 152 Q 118 164 118 176 V 192 Q 118 208 139 212 L 178 220 Q 182 221 179 225 L 158 258 Q 156 261 152 260 L 109 248 Q 72 238 72 200 V 178 Q 72 156 88 140 L 112 116 Q 122 106 122 98 V 92 Q 122 88 126 88 Z";

export const BRAND_PATHS = [
  { layer: "horn-left", d: HORN, transform: "" },
  { layer: "horn-right", d: HORN, transform: "translate(512 0) scale(-1 1)" },
  { layer: "ox-face", d: "M 204 222 H 308 Q 312 222 315 226 L 334 262 Q 337 266 333 270 L 306 292 L 286 358 Q 284 362 286 366 L 292 374 Q 295 378 292 383 L 283 399 Q 280 404 274 404 H 238 Q 232 404 229 399 L 220 383 Q 217 378 220 374 L 226 366 Q 228 362 226 358 L 206 292 L 179 270 Q 175 266 178 262 L 197 226 Q 200 222 204 222 Z", transform: "" },
] as const;

export const BRAND_GOLD = "#C8B560";
export const BRAND_GRAPHITE = "#151719";
