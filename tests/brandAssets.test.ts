import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { BrandMark } from "../src/components/brand/BrandMark";

const BRAND_ASSETS = [
  "design/logo/ox-mark.svg",
  "design/logo/ox-icon.svg",
  "public/favicon.svg",
  "src/assets/brand/oxaudit-mark.svg",
  "src/assets/brand/oxaudit-lockup.svg",
  "src/assets/brand/oxaudit-app-icon-v1.svg",
] as const;

function normalizePathData(pathData: string): string {
  return pathData.replace(/\s+/g, " ").trim();
}

type PathSignature = { layer: string; pathData: string; transform: string };

function pathSignatures(svg: string): PathSignature[] {
  return Array.from(svg.matchAll(/<path\b([^>]*)>/gi)).flatMap((match) => {
    const attributes = match[1];
    const layer = attributes.match(/\bdata-brand-layer=["']([\s\S]*?)["']/i)?.[1];
    if (!layer) return [];

    const pathData = attributes.match(/\bd=["']([\s\S]*?)["']/i)?.[1];
    const transform = attributes.match(/\btransform=["']([\s\S]*?)["']/i)?.[1] ?? "";

    assert.ok(pathData, "every brand path must contain path data");
    return [{ layer, pathData: normalizePathData(pathData), transform }];
  });
}

test("every shipped brand entry point matches the magnifier-x mark", () => {
  const runtimeSvg = renderToStaticMarkup(createElement(BrandMark));
  const runtimeGeometry = pathSignatures(runtimeSvg);

  assert.deepEqual(
    runtimeGeometry.map(({ layer, transform }) => [layer, transform]),
    [
      ["lens", ""],
      ["handle", ""],
      ["cross-first", ""],
      ["cross-second", ""],
    ],
  );

  const mismatches = BRAND_ASSETS.filter(
    (path) => {
      try {
        assert.deepEqual(pathSignatures(readFileSync(path, "utf8")), runtimeGeometry);
        return false;
      } catch {
        return true;
      }
    },
  );

  assert.deepEqual(mismatches, []);
});

test("standalone icons use gold on a graphite tile with transparent outer margins", () => {
  for (const path of [
    "design/logo/ox-icon.svg",
    "public/favicon.svg",
    "src/assets/brand/oxaudit-app-icon-v1.svg",
  ]) {
    const source = readFileSync(path, "utf8").toLowerCase();
    assert.match(source, /#151719/);
    assert.match(source, /#c8b560/);
    assert.match(source, /<rect x="24" y="24" width="464" height="464" rx="104"/);
  }
});
