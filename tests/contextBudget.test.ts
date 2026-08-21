import assert from "node:assert/strict";
import { test } from "node:test";
import {
  buildContextBudget,
  estimateMessageTokens,
} from "../src/lib/contextBudget";

test("context estimates include message framing and character content", () => {
  assert.equal(
    estimateMessageTokens([{ content: "12345678" }, { content: "1234" }]),
    11,
  );
});

test("context budget reserves output capacity and reports thresholds", () => {
  const warning = buildContextBudget(7_000, 10_000, 1_000);
  assert.equal(warning.usedTokens, 8_000);
  assert.equal(warning.percent, 80);
  assert.equal(warning.tone, "warning");
  assert.equal(warning.remainingTokens, 2_000);

  const critical = buildContextBudget(9_500, 10_000, 1_000);
  assert.equal(critical.percent, 100);
  assert.equal(critical.tone, "critical");
  assert.equal(critical.remainingTokens, 0);
});
