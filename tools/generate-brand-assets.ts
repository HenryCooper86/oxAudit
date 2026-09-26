import { writeFileSync } from "node:fs";
import { BRAND_PATHS, BRAND_GOLD, BRAND_GRAPHITE } from "../src/components/brand/geometry";

const paths = BRAND_PATHS.map(({ layer, d, transform }) =>
  `  <path data-brand-layer="${layer}" fill="${BRAND_GOLD}" d="${d}"${transform ? ` transform="${transform}"` : ""} />`
).join("\n");
const svg = (title: string, description: string, body: string, viewBox = "0 0 512 512") =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${viewBox}" role="img" aria-labelledby="title description">\n  <title id="title">${title}</title>\n  <desc id="description">${description}</desc>\n${body}\n</svg>\n`;
const description = "A magnifier whose lens holds an x: the o and x of oxAudit, and the act of auditing a system closely.";
const mark = svg("oxAudit mark", description, paths);
const icon = svg("oxAudit app icon", description, `  <rect x="24" y="24" width="464" height="464" rx="104" fill="${BRAND_GRAPHITE}" />\n${paths}`);
const lockup = svg("oxAudit", `${description} Followed by the product name.`, `  <g transform="translate(0 0) scale(0.125)">\n${paths}\n  </g>\n  <text x="72" y="46" fill="${BRAND_GOLD}" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" font-size="40" font-weight="600" letter-spacing="-1.2">oxAudit</text>`, "0 0 286 64");
for (const path of ["src/assets/brand/oxaudit-mark.svg", "design/logo/ox-mark.svg"]) writeFileSync(path, mark);
for (const path of ["src/assets/brand/oxaudit-app-icon-v1.svg", "design/logo/ox-icon.svg", "public/favicon.svg"]) writeFileSync(path, icon);
writeFileSync("src/assets/brand/oxaudit-lockup.svg", lockup);
console.log("Generated six brand SVGs from shared geometry.");
