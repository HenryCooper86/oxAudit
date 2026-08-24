import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

/**
 * A Rust struct and its TypeScript interface are two halves of one wire format.
 * Nothing enforced that, and the failure mode is silent rather than loud:
 *
 *   1. A field is added to the Rust struct with `#[serde(default)]`, which it
 *      needs so records written before the field existed still load.
 *   2. The TypeScript interface is not updated, so the GUI builds a payload
 *      without it.
 *   3. Rust deserializes the payload, applies the default, and writes it back.
 *
 * The value is gone, no error is raised anywhere, and the only symptom is a
 * field that will not stick. This makes step 2 impossible.
 *
 * `AppSettings` is where it was first caught. `Finding` matters for the same
 * reason: it carries the analysis tier, and a finding that loses it silently
 * downgrades to claiming no syntax verification ran.
 */

const RUST_MODELS = "src-tauri/src/models.rs";
const TS_TYPES = "src/lib/types.ts";

/** Extract the body of a named `pub struct` from the Rust source. */
function rustStructBody(source: string, name: string): string {
  const start = source.indexOf(`pub struct ${name} {`);
  assert.notEqual(start, -1, `${name} not found in ${RUST_MODELS}`);
  const open = source.indexOf("{", start);
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open + 1, index);
    }
  }
  throw new Error(`unterminated struct ${name}`);
}

/** Extract the body of a named `export interface` from the TypeScript source. */
function tsInterfaceBody(source: string, name: string): string {
  const start = source.indexOf(`export interface ${name} {`);
  assert.notEqual(start, -1, `${name} not found in ${TS_TYPES}`);
  const open = source.indexOf("{", start);
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open + 1, index);
    }
  }
  throw new Error(`unterminated interface ${name}`);
}

/** Field names declared at the top level of a Rust struct body. */
function rustFieldNames(body: string): string[] {
  const names: string[] = [];
  let depth = 0;
  for (const rawLine of body.split("\n")) {
    const line = rawLine.trim();
    // Only read declarations at the struct's own level, not inside a nested type.
    const opens = (line.match(/[<({[]/g) ?? []).length;
    const closes = (line.match(/[>)}\]]/g) ?? []).length;
    if (depth === 0 && line.startsWith("pub ")) {
      const match = line.match(/^pub ([a-z0-9_]+)\s*:/);
      if (match) names.push(match[1]);
    }
    depth += opens - closes;
    if (depth < 0) depth = 0;
  }
  return names;
}

/** Property names declared at the top level of a TypeScript interface body. */
function tsPropertyNames(body: string): string[] {
  const names: string[] = [];
  let depth = 0;
  let inBlockComment = false;
  for (const rawLine of body.split("\n")) {
    const line = rawLine.trim();
    if (inBlockComment) {
      if (line.includes("*/")) inBlockComment = false;
      continue;
    }
    if (line.startsWith("/*")) {
      if (!line.includes("*/")) inBlockComment = true;
      continue;
    }
    if (line.startsWith("//") || line.startsWith("*")) continue;
    if (depth === 0) {
      const match = line.match(/^([A-Za-z0-9_]+)\??\s*:/);
      if (match) names.push(match[1]);
    }
    depth += (line.match(/[<({[]/g) ?? []).length;
    depth -= (line.match(/[>)}\]]/g) ?? []).length;
    if (depth < 0) depth = 0;
  }
  return names;
}

/** `agent_allowed_fetch_hosts` -> `agentAllowedFetchHosts`, matching serde. */
function toCamelCase(name: string): string {
  return name.replace(/_([a-z0-9])/g, (_, char: string) => char.toUpperCase());
}

/** Structs that cross the IPC boundary and must mirror each other exactly. */
const MIRRORED = ["AppSettings", "Finding"];

for (const name of MIRRORED) {
  test(`every Rust ${name} field is declared in the TypeScript interface`, () => {
    const rust = rustFieldNames(rustStructBody(readFileSync(RUST_MODELS, "utf8"), name));
    const typescript = new Set(
      tsPropertyNames(tsInterfaceBody(readFileSync(TS_TYPES, "utf8"), name)),
    );
    assert.ok(rust.length > 0, `no fields parsed from the Rust ${name} struct`);
    const missing = rust.map(toCamelCase).filter((field) => !typescript.has(field));
    assert.deepEqual(
      missing,
      [],
      `${name} fields exist in Rust but not in ${TS_TYPES}: ${missing.join(", ")}. ` +
        "A value crossing the IPC boundary would drop them.",
    );
  });
}

test("the TypeScript AppSettings interface declares nothing Rust will not accept", () => {
  const rust = new Set(
    rustFieldNames(rustStructBody(readFileSync(RUST_MODELS, "utf8"), "AppSettings")).map(
      toCamelCase,
    ),
  );
  const typescript = tsPropertyNames(
    tsInterfaceBody(readFileSync(TS_TYPES, "utf8"), "AppSettings"),
  );

  assert.ok(typescript.length > 0, "no properties parsed from the TypeScript interface");

  const extra = typescript.filter((field) => !rust.has(field));
  assert.deepEqual(
    extra,
    [],
    `${TS_TYPES} declares AppSettings fields Rust does not have: ${extra.join(", ")}. ` +
      "Either the Rust struct is missing them or the interface is stale.",
  );
});

test("the assistant's fetch allow-list survives the round trip", () => {
  // The specific field this contract was written for: it governs where the
  // assistant may send bytes, so losing it silently widens nothing but does
  // quietly discard a security decision the user made.
  const rust = rustFieldNames(rustStructBody(readFileSync(RUST_MODELS, "utf8"), "AppSettings"));
  assert.ok(
    rust.includes("agent_allowed_fetch_hosts"),
    "agent_allowed_fetch_hosts is missing from the Rust AppSettings struct",
  );

  const types = readFileSync(TS_TYPES, "utf8");
  assert.match(types, /agentAllowedFetchHosts:\s*string\[\]/);

  // The Settings screen must copy the array rather than share it with the store.
  const page = readFileSync("src/pages/SettingsPage.tsx", "utf8");
  assert.match(
    page,
    /agentAllowedFetchHosts:\s*\[\.\.\./,
    "cloneSettings must copy agentAllowedFetchHosts, not alias the store's array",
  );
});
