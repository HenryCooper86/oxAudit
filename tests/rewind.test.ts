import assert from "node:assert/strict";
import test from "node:test";
import { planRewind, type RewindTarget } from "../src/lib/rewind";

const conversation: RewindTarget[] = [
  { id: "m1", role: "user", content: "audit this repo" },
  { id: "m2", role: "assistant", content: "found 3 issues" },
  { id: "m3", role: "user", content: "focus on the auth module" },
  { id: "m4", role: "assistant", content: "the session cookie is not httpOnly" },
];

test("rewinding to a user turn keeps everything before it and restores its text", () => {
  const plan = planRewind(conversation, "m3");

  assert.deepEqual(plan, {
    keepCount: 2,
    restoredInput: "focus on the auth module",
    discardedCount: 2,
  });
});

test("rewinding to the first turn discards the whole conversation", () => {
  const plan = planRewind(conversation, "m1");

  assert.equal(plan?.keepCount, 0);
  assert.equal(plan?.discardedCount, 4);
  assert.equal(plan?.restoredInput, "audit this repo");
});

test("rewinding to the last user turn still discards the answer that followed it", () => {
  const trailing: RewindTarget[] = [
    { id: "m1", role: "user", content: "first" },
    { id: "m2", role: "user", content: "second" },
  ];

  const plan = planRewind(trailing, "m2");

  assert.equal(plan?.keepCount, 1, "only the earlier turn survives");
  assert.equal(plan?.discardedCount, 1);
});

test("an assistant turn is not a rewind target", () => {
  // Rewinding onto the model's own output would leave the preceding question
  // answered by nothing, so it is refused rather than silently shifted.
  assert.equal(planRewind(conversation, "m2"), null);
  assert.equal(planRewind(conversation, "m4"), null);
});

test("an unknown message id plans nothing rather than truncating to zero", () => {
  assert.equal(planRewind(conversation, "does-not-exist"), null);
  assert.equal(planRewind([], "m1"), null);
});
