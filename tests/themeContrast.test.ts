import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// This protects readable rendered color combinations, not specific palette values.
// Expectations use WCAG's independent relative-luminance/contrast definition.
const css = readFileSync(new URL("../src/index.css", import.meta.url), "utf8");
type Rgb = [number, number, number];
function rgb(value: string): Rgb {
  assert.match(value, /^#[\da-f]{6}$/i);
  return [1, 3, 5].map((offset) => parseInt(value.slice(offset, offset + 2), 16)) as Rgb;
}
function luminance(color: Rgb): number {
  const linear = color.map((channel) => {
    const scaled = channel / 255;
    return scaled <= 0.04045 ? scaled / 12.92 : ((scaled + 0.055) / 1.055) ** 2.4;
  });
  return linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722;
}
function contrast(left: Rgb, right: Rgb): number {
  const [low, high] = [luminance(left), luminance(right)].sort((a, b) => a - b);
  return (high + 0.05) / (low + 0.05);
}
function blend(value: string, background: Rgb): Rgb {
  const match = /^rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)$/.exec(value);
  assert.ok(match, `Unsupported badge fill ${value}`);
  const alpha = Number(match[4]);
  return background.map((channel, index) => Number(match[index + 1]) * alpha + channel * (1 - alpha)) as Rgb;
}
for (const theme of ["dark", "light"]) {
  const block = new RegExp(`\\[data-theme="${theme}"\\]\\s*\\{([\\s\\S]*?)\\n\\}`).exec(css)?.[1];
  assert.ok(block, `Missing ${theme} palette`);
  const tokens = Object.fromEntries([...block.matchAll(/--([\w-]+):\s*([^;]+);/g)].map((match) => [match[1], match[2].trim()]));
  test(`${theme} normal and semantic text stays readable on all panel surfaces`, () => {
    const failures: string[] = [];
    const colors = ["text-primary", "text-secondary", "text-muted", "accent", "success", "warning", "error", "info", "sev-critical", "sev-high", "sev-medium", "sev-low", "sev-info", "sev-unknown"];
    for (const surface of ["surface-primary", "surface-secondary", "surface-tertiary"]) {
      for (const color of colors) {
        const ratio = contrast(rgb(tokens[color]), rgb(tokens[surface]));
        if (ratio < 4.5) failures.push(`${color} on ${surface}: ${ratio.toFixed(3)}:1`);
      }
      for (const color of colors.filter((value) => value.startsWith("sev-") || ["success", "warning", "error", "info"].includes(value))) {
        const ratio = contrast(rgb(tokens[color]), blend(tokens[`${color}-subtle`], rgb(tokens[surface])));
        if (ratio < 4.5) failures.push(`${color} on its ${surface} badge: ${ratio.toFixed(3)}:1`);
      }
    }
    assert.deepEqual(failures, [], failures.join("\n"));
  });
  test(`${theme} primary button text remains readable on normal and hover fills`, () => {
    for (const fill of ["accent", "accent-hover"]) {
      assert.ok(contrast(rgb(tokens["accent-contrast"]), rgb(tokens[fill])) >= 4.5, `${fill} button text`);
    }
  });
  test(`${theme} editable control boundaries are distinguishable from adjacent surfaces`, () => {
    for (const surface of ["surface-primary", "surface-secondary", "surface-tertiary"]) {
      const background = rgb(tokens[surface]);
      const boundary = tokens["control-border"] ? rgb(tokens["control-border"]) : blend(tokens.border, background);
      assert.ok(contrast(boundary, background) >= 3, `control boundary on ${surface}`);
    }
  });
}
