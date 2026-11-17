import assert from "node:assert/strict";
import test from "node:test";

import { scanArguments, supportsCacheDir } from "../editors/vscode/src/cli.ts";
import { reportableFindings } from "../editors/vscode/src/findings.ts";

/**
 * The VS Code extension shows findings as editor diagnostics. A finding the
 * project's review policy dismissed (false positive, accepted risk,
 * suppressed) does not fail `--fail-on`, so it must not reappear as a
 * squiggle either; undecided and confirmed findings stay.
 */
test("dismissed findings are not shown as diagnostics", () => {
  const findings = [
    { id: "undecided" },
    { id: "candidate", review: { state: "candidate" } },
    { id: "confirmed", review: { state: "confirmed" } },
    { id: "false-positive", review: { state: "falsePositive" } },
    { id: "accepted-risk", review: { state: "acceptedRisk" } },
    { id: "suppressed", review: { state: "suppressed" } },
    { id: "null-review", review: null },
  ];
  assert.deepEqual(
    reportableFindings(findings).map((finding) => finding.id),
    ["undecided", "candidate", "confirmed", "null-review"],
  );
});

/**
 * The extension passes `--cache-dir` only to a CLI that accepts it. An older
 * CLI treats an unknown flag as a usage error, so guessing wrong would stop
 * the editor scanning at all.
 */
test("the cache directory is offered only to a CLI whose help lists it", () => {
  const current = "Options:\n      --db <DB>\n          Keep the run\n\n      --cache-dir <DIR>\n          Keep the catalog\n";
  const older = "Options:\n      --db <DB>\n          Keep the run in this database\n";
  assert.equal(supportsCacheDir(current), true);
  assert.equal(supportsCacheDir(older), false);
  assert.equal(supportsCacheDir("see --cache-directory for details"), false);
  assert.equal(supportsCacheDir(""), false);

  assert.deepEqual(scanArguments("/work/app"), ["scan", "/work/app", "--format", "json", "--quiet"]);
  assert.deepEqual(scanArguments("/work/app", "/store/cache"), [
    "scan", "/work/app", "--format", "json", "--quiet", "--cache-dir", "/store/cache",
  ]);
  assert.deepEqual(scanArguments("/work/app", ""), ["scan", "/work/app", "--format", "json", "--quiet"]);
});
