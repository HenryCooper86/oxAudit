import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

test("quality recording preserves CLI JSON, binary identity, exact corpus pin and refuses modified ground truth", async () => {
  const owned = await mkdtemp(path.join(tmpdir(), "oxaudit-quality-record-"));
  const git = (args: string[]) => execFileSync("git", args, { encoding: "utf8" }).trim();
  try {
    const corpus = path.join(owned, "corpus"); git(["init", "--quiet", corpus]);
    await writeFile(path.join(corpus, "expectedresults-1.2.csv"), "# fixture\ncase,cmdi,true,78\ncase2,cmdi,false,78\n");
    git(["-C", corpus, "add", "."]); git(["-C", corpus, "-c", "user.name=Benchmark test", "-c", "user.email=benchmark-test@localhost", "commit", "--quiet", "-m", "fixture"]);
    const pin = git(["-C", corpus, "rev-parse", "HEAD"]), cliFixture = path.join(owned, "cli.mjs");
    await writeFile(cliFixture, String.raw`import fs from 'node:fs'; const args=process.argv.slice(2); if(args[0]!=='external-benchmark'||!args.includes('--json'))throw Error('wrong invocation'); fs.writeFileSync(args[args.indexOf('--output')+1],JSON.stringify({suite:'OWASP Benchmark 1.2',cases:2,runtimeMs:3,coveredTotals:{truePositives:1,falsePositives:0,trueNegatives:1,falseNegatives:0},uncoveredTotals:{truePositives:0,falsePositives:0,trueNegatives:0,falseNegatives:0},categories:[{category:'cmdi',cwe:78,covered:true,truePositives:1,falsePositives:0,trueNegatives:1,falseNegatives:0}]}));`);
    const { recordQuality } = await import("../tools/record-quality-benchmark.mjs");
    const output = path.join(owned, "quality");
    const result = await recordQuality({ cli: process.execPath, cliArgs: [cliFixture], corpus, output, expectedCommit: pin });
    assert.equal(result.provenance.benchmarkCommit, pin);
    assert.match(result.provenance.cliSha256, /^[0-9a-f]{64}$/);
    assert.equal(JSON.parse(await readFile(path.join(output, "raw.json"), "utf8")).categories[0].truePositives, 1);
    assert.equal(JSON.parse(await readFile(path.join(output, "result.json"), "utf8")).report.cases, 2);
    await assert.rejects(recordQuality({ cli: process.execPath, cliArgs: [cliFixture], corpus, output: path.join(owned, "wrong"), expectedCommit: "f".repeat(40) }), /pin/);
    await writeFile(path.join(corpus, "expectedresults-1.2.csv"), "tampered");
    await assert.rejects(recordQuality({ cli: process.execPath, cliArgs: [cliFixture], corpus, output: path.join(owned, "dirty"), expectedCommit: pin }), /modified/);
  } finally { await rm(owned, { recursive: true, force: true }); }
});
