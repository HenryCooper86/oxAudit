import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("rebuilding the corpus preserves overlapping secret expectations and stable fixture IDs", () => {
  const directory = mkdtempSync(join(tmpdir(), "oxaudit-corpus-"));
  const corpus = join(directory, "benchmarks/corpus");
  mkdirSync(join(corpus, "secrets"), { recursive: true });
  for (const name of [
    "sentry-token__positive__client.js",
    "plaid-api-key__positive__bank_sync.py",
    "generic-api-key__positive__literal.js",
  ]) {
    writeFileSync(join(corpus, "secrets", name), "inert fixture\n");
  }
  try {
    const script = resolve("tools/build-corpus-suite.mjs");
    const build = spawnSync(process.execPath, [script], { cwd: directory, encoding: "utf8" });
    assert.equal(build.status, 0, build.stderr);
    const suite = JSON.parse(readFileSync(join(corpus, "suite.json"), "utf8"));
    const targets = new Map<string, { expected: unknown }>(
      suite.targets.map((target: { id: string; expected: unknown }) => [target.id, target]),
    );
    assert.deepEqual(targets.get("sentry-token.positive.client")?.expected, [
      { ruleId: "sentry-token", minimum: 1 },
      { ruleId: "generic-api-key", minimum: 1 },
    ]);
    assert.deepEqual(targets.get("plaid-api-key.positive.bank-sync")?.expected, [
      { ruleId: "plaid-api-key", minimum: 1 },
      { ruleId: "generic-password", minimum: 1 },
    ]);
    assert.deepEqual(targets.get("generic-api-key.positive.literal")?.expected, [
      { ruleId: "generic-api-key", minimum: 1 },
    ]);
    const check = spawnSync(process.execPath, [script, "--check"], { cwd: directory, encoding: "utf8" });
    assert.equal(check.status, 0, check.stderr);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
