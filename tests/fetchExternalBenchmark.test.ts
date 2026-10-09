import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";

test("fresh real git clone with inherited output reaches the exact pin and never silently replaces another checkout", async () => {
  const owned = await mkdtemp(path.join(tmpdir(), "oxaudit-fetch-test-"));
  const git = (args: string[]) => execFileSync("git", args, { encoding: "utf8" }).trim();
  try {
    const repository = path.join(owned, "origin"), target = path.join(owned, "checkout");
    git(["init", "--quiet", repository]);
    await writeFile(path.join(repository, "case.java"), "first\n");
    const commit = () => { git(["-C", repository, "add", "."]); git(["-C", repository, "-c", "user.name=Benchmark test", "-c", "user.email=benchmark-test@localhost", "commit", "--quiet", "-m", "fixture"]); return git(["-C", repository, "rev-parse", "HEAD"]); };
    const pinned = commit(); await writeFile(path.join(repository, "case.java"), "second\n"); const other = commit();
    const script = `import { fetchBenchmark } from ${JSON.stringify(pathToFileURL(path.resolve("tools/fetch-external-benchmark.mjs")).href)}; const options=JSON.parse(process.argv[1]); await fetchBenchmark(options); console.log('FETCH_COMPLETED');`;
    const run = (commit: string) => spawnSync(process.execPath, ["--input-type=module", "-e", script, JSON.stringify({ repository, commit, target })], { encoding: "utf8" });
    const fetched = run(pinned);
    assert.equal(fetched.status, 0, fetched.stderr);
    assert.match(fetched.stdout, /FETCH_COMPLETED/);
    assert.equal(git(["-C", target, "rev-parse", "HEAD"]), pinned);
    assert.equal(await readFile(path.join(target, "case.java"), "utf8"), "first\n");
    assert.equal(run(pinned).status, 0);
    const refused = run(other); assert.notEqual(refused.status, 0); assert.match(refused.stderr, /different commit/);
    assert.equal(git(["-C", target, "rev-parse", "HEAD"]), pinned);
  } finally { await rm(owned, { recursive: true, force: true }); }
});
