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

function firstPathData(svg: string): string {
  const match = svg.match(/<path\b[^>]*\bd=["']([\s\S]*?)["']/i);
  assert.ok(match, "brand asset must contain a path");
  return normalizePathData(match[1]);
}

test("every shipped brand entry point renders the same mark geometry", () => {
  const runtimeSvg = renderToStaticMarkup(createElement(BrandMark));
  const runtimeGeometry = firstPathData(runtimeSvg);

  const mismatches = BRAND_ASSETS.filter(
    (path) => firstPathData(readFileSync(path, "utf8")) !== runtimeGeometry,
  );

  assert.deepEqual(mismatches, []);
});

test("standalone icons use the canonical gold-on-near-black palette", () => {
  for (const path of [
    "design/logo/ox-icon.svg",
    "public/favicon.svg",
    "src/assets/brand/oxaudit-app-icon-v1.svg",
  ]) {
    const source = readFileSync(path, "utf8").toLowerCase();
    assert.match(source, /#0f0f0f/);
    assert.match(source, /#c8b560/);
  }
});
