import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

for (const path of [
  "schemas/oxaudit-run.schema.json",
  "schemas/export-preview.schema.json",
  "schemas/import-preview.schema.json",
  "benchmarks/schema/benchmark-suite.schema.json",
  "benchmarks/schema/benchmark-result.schema.json",
]) {
  test(`${path} is a versioned JSON schema`, async () => {
    const schema = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
    assert.equal(typeof schema.$schema, "string");
    assert.equal(typeof schema.$id, "string");
    assert.equal(schema.type, "object");
  });
}
