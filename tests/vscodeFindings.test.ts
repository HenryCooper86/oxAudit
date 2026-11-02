import assert from "node:assert/strict";
import test from "node:test";

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
