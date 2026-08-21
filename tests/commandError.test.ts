import assert from "node:assert/strict";
import test from "node:test";
import { normalizeCommandError } from "../src/lib/commandError";

test("a native typed error keeps its code and safe message", () => {
  assert.deepEqual(
    normalizeCommandError({
      code: "policyInvalid",
      message: "Project policy is invalid",
      detail: "entries[0].reason is required",
      retryable: false,
    }),
    {
      code: "policyInvalid",
      message: "Project policy is invalid",
      detail: "entries[0].reason is required",
      retryable: false,
    },
  );
});

test("an unknown rejection becomes a safe scan failure", () => {
  assert.deepEqual(normalizeCommandError("bridge unavailable"), {
    code: "scanFailed",
    message: "bridge unavailable",
    detail: null,
    retryable: true,
  });
});

test("unknown object fields never leak into diagnostic detail", () => {
  assert.deepEqual(
    normalizeCommandError({ message: "failed", secret: "do-not-copy" }),
    {
      code: "scanFailed",
      message: "failed",
      detail: null,
      retryable: true,
    },
  );
});
