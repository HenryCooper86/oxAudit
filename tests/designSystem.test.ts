import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { extname, join } from "node:path";
import test from "node:test";

/**
 * Visual contracts for the design system. The rules began as a port of
 * y-agent's `y-gui/src/__tests__/designSystemCompliance.test.ts`; since
 * 2026-11-18 the shell and scales follow oxFuzz (`crates/hf-gui`), which adds
 * a 12px card radius and one named composer radius.
 *
 * The rules these lock down are not stylistic preferences — each one is a
 * regression that already happened once, or a property the token layer needs
 * in order to theme correctly.
 */

const STYLESHEET = "src/index.css";

function readStylesheet(): string {
  return readFileSync(STYLESHEET, "utf8");
}

/** Every production source file, excluding tests and build output. */
function sourceFiles(): Array<[string, string]> {
  const files: Array<[string, string]> = [];

  const visit = (directory: string) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(path);
      } else if ([".ts", ".tsx", ".css"].includes(extname(entry.name))) {
        files.push([path, readFileSync(path, "utf8")]);
      }
    }
  };

  visit("src");
  return files;
}

/** Extract the body of a top-level CSS rule by selector. */
function cssRule(source: string, selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = source.match(new RegExp(`${escaped}\\s*\\{([^}]*)\\}`, "s"));
  assert.ok(match, `missing CSS rule for ${selector}`);
  return match[1];
}

/** Names of the custom properties declared inside one rule body. */
function declaredVariables(body: string): Set<string> {
  return new Set(Array.from(body.matchAll(/(--[\w-]+)\s*:/g), (m) => m[1]));
}

/** className string literals and template literals, with their file+line. */
function classAttributes(): Array<{ file: string; line: number; value: string }> {
  const pattern = /className=(?:"([^"]*)"|\{`([^`]*)`\})/gs;
  const found: Array<{ file: string; line: number; value: string }> = [];

  for (const [file, source] of sourceFiles()) {
    if (extname(file) !== ".tsx") continue;
    for (const match of source.matchAll(pattern)) {
      found.push({
        file,
        line: source.slice(0, match.index).split("\n").length,
        value: match[1] ?? match[2] ?? "",
      });
    }
  }

  return found;
}

test("radius system is 4/8/12px plus one named composer radius, and nothing else", () => {
  const styles = readStylesheet();

  assert.match(styles, /--radius-sm:\s*4px;/);
  assert.match(styles, /--radius-md:\s*8px;/);
  assert.match(styles, /--radius-lg:\s*12px;/);
  assert.match(styles, /--radius-composer:\s*16px;/);

  const declared = Array.from(styles.matchAll(/(--radius-[\w-]+)\s*:/g), (m) => m[1]).sort();
  assert.deepEqual(declared, ["--radius-composer", "--radius-lg", "--radius-md", "--radius-sm"]);
});

test("no source file uses a radius above the 12px card radius", () => {
  const violations = sourceFiles()
    .filter(([, source]) => /\brounded-(xl|2xl|3xl)\b/.test(source))
    .map(([file]) => file);

  assert.deepEqual(violations, []);
});

test("the 16px composer radius is reserved for the assistant composer", () => {
  // The one sanctioned radius above the card radius belongs to the AI
  // assistant's floating composer. Anywhere else it would be a fourth step.
  const allowed = (file: string) =>
    file === join("src", "pages", "Assistant.tsx") || file.startsWith(join("src", "components", "chat") + "/");
  const violations = sourceFiles()
    .filter(([file]) => extname(file) !== ".css")
    .filter(([file, source]) => /\brounded-composer\b/.test(source) && !allowed(file))
    .map(([file]) => file);

  assert.deepEqual(violations, []);
});

test("surface-card is the primary surface with a hairline border, 12px radius and small shadow", () => {
  const card = cssRule(readStylesheet(), ".surface-card");

  assert.match(card, /background-color:\s*var\(--surface-primary\);/);
  assert.match(card, /border:\s*1px solid var\(--border\);/);
  assert.match(card, /border-radius:\s*var\(--radius-lg\);/);
  assert.match(card, /box-shadow:\s*var\(--elevation-sm\);/);
});

test("no source file uses a decorative gradient", () => {
  const violations = sourceFiles()
    .filter(([, source]) => /[a-z-]+-gradient\(|\bbg-gradient-/.test(source))
    .map(([file]) => file);

  assert.deepEqual(violations, []);
});

test("elevation stays on the sm/md/lg scale", () => {
  const violations = sourceFiles()
    .filter(([, source]) => /\bshadow-(xl|2xl)\b/.test(source))
    .map(([file]) => file);

  assert.deepEqual(violations, []);
});

test("body text sits at zero letter spacing", () => {
  const styles = readStylesheet();

  assert.match(cssRule(styles, "body"), /letter-spacing:\s*0;/);
  assert.doesNotMatch(styles, /letter-spacing:\s*-[\d.]+(?:em|px|rem)/);
});

test("colors come from the token layer, never from a raw Tailwind palette", () => {
  const palette = /\b(?:bg|text|border|divide|outline|ring|fill|stroke|from|via|to)-(?:ink|slate|stone|zinc|gray|neutral|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}\b/;

  const violations = sourceFiles()
    .filter(([file]) => extname(file) === ".tsx")
    .flatMap(([file, source]) =>
      source
        .split("\n")
        .map((line, index) => ({ line, number: index + 1 }))
        .filter(({ line }) => palette.test(line))
        .map(({ number }) => `${file}:${number}`),
    );

  assert.deepEqual(violations, []);
});

test("every dark token has a light counterpart", () => {
  const styles = readStylesheet();

  const dark = declaredVariables(cssRule(styles, ':root,\n[data-theme="dark"]'));
  const light = declaredVariables(cssRule(styles, '[data-theme="light"]'));

  const missing = [...dark].filter((name) => !light.has(name)).sort();

  // `color-scheme` is a property, not a token; everything else must pair up.
  assert.deepEqual(missing, []);
});

test("no themed token is dead — each is aliased into Tailwind or used by a rule", () => {
  const styles = readStylesheet();

  const dark = declaredVariables(cssRule(styles, ':root,\n[data-theme="dark"]'));
  const aliasBlock = styles.match(/@theme inline\s*\{([^}]*)\}/s)?.[1] ?? "";
  const rules = styles.slice(styles.indexOf("}", styles.indexOf("@theme {")) + 1);

  const unused = [...dark]
    .filter((name) => !aliasBlock.includes(`var(${name})`) && !rules.includes(`var(${name})`))
    .sort();

  assert.deepEqual(unused, []);
});

test("no hover state resolves to the same color as its own base", () => {
  // Regression guard: collapsing a palette onto tokens can silently map a
  // hover and its base onto one value, leaving the control with no feedback.
  const colorUtility = /^(bg|text|border)-[\w-]+$/;
  const violations: string[] = [];

  for (const { file, line, value } of classAttributes()) {
    const tokens = value.split(/\s+/);
    const base = new Set(tokens.filter((token) => colorUtility.test(token)));

    for (const token of tokens) {
      const hover = /^hover:((?:bg|text|border)-[\w-]+)$/.exec(token);
      if (hover && base.has(hover[1])) violations.push(`${file}:${line} ${token}`);
    }
  }

  assert.deepEqual(violations, []);
});
