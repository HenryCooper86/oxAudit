import assert from "node:assert/strict";
import test from "node:test";
import { fmtDuration } from "../src/lib/format";

test("duration rounding carries into minutes instead of displaying sixty seconds", () => {
  assert.equal(fmtDuration(119_499), "1m 59s");
  assert.equal(fmtDuration(119_500), "2m 0s");
});
