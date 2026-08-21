import assert from "node:assert/strict";
import { test } from "node:test";
import {
  nextSearchIndex,
  normalizeSearchQuery,
  splitSearchMatches,
} from "../src/lib/chatSearch";

test("conversation search trims a query and matches without case sensitivity", () => {
  assert.equal(normalizeSearchQuery("  CVE-2026  "), "CVE-2026");
  assert.deepEqual(splitSearchMatches("CVE cve CvE", "cve"), [
    { text: "CVE", match: true },
    { text: " ", match: false },
    { text: "cve", match: true },
    { text: " ", match: false },
    { text: "CvE", match: true },
  ]);
});

test("empty and absent search queries preserve the original text", () => {
  assert.deepEqual(splitSearchMatches("hello", "   "), [
    { text: "hello", match: false },
  ]);
  assert.deepEqual(splitSearchMatches("hello", "CVE"), [
    { text: "hello", match: false },
  ]);
});

test("search navigation wraps in both directions", () => {
  assert.equal(nextSearchIndex(2, 3, 1), 0);
  assert.equal(nextSearchIndex(0, 3, -1), 2);
  assert.equal(nextSearchIndex(4, 0, 1), 0);
});
