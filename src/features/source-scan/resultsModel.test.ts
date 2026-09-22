import { expect, test } from "vitest";
import { filterFindings, sortFindings } from "./resultsModel";
import type { Finding, Severity } from "../../lib/types";
import type { ResultsQuery } from "./types";
const query: ResultsQuery = { view: "open", category: "all", severity: "all", scope: "all", language: "all", search: "", sort: "severity" };
const finding = (id: string, diffStatus: Finding["diffStatus"], scope: Finding["scope"] = "production") => ({ fingerprint: id, diffStatus, scope } as Finding);
test("new since baseline intersects every review and scope view", () => {
  const findings = [finding("new", "new"), finding("old", "unchanged"), finding("test", "new", "test"), { ...finding("closed", "new"), review: { state: "acceptedRisk" } } as Finding];
  expect(filterFindings(findings, { ...query, newOnly: true }).map(f => f.fingerprint)).toEqual(["new"]);
  expect(filterFindings(findings, { ...query, view: "otherScopes", newOnly: true }).map(f => f.fingerprint)).toEqual(["test"]);
  expect(filterFindings(findings, { ...query, view: "closed", newOnly: true }).map(f => f.fingerprint)).toEqual(["closed"]);
  expect(filterFindings([finding("resolved", "resolved")], { ...query, view: "resolved", newOnly: true })).toEqual([]);
});

const ordered = (overrides: Partial<Finding>): Finding =>
  ({ fingerprint: Math.random().toString(36).slice(2), scope: "production", ...overrides } as Finding);

const SORTABLE: Finding[] = [
  ordered({ severity: "low", ruleId: "js-eval", filePath: "src/a.js", line: 40, column: 1 }),
  ordered({ severity: "critical", ruleId: "py-exec", filePath: "src/z.py", line: 2, column: 1 }),
  ordered({ severity: "critical", ruleId: "js-eval", filePath: "src/a.js", line: 10, column: 3 }),
  ordered({ severity: "high", ruleId: "go-weak-rand", filePath: "src/m.go", line: 7, column: 1 }),
];

test("severity sort puts the worst first and breaks ties by location", () => {
  expect(sortFindings(SORTABLE, "severity").map(f => [f.severity, f.filePath, f.line])).toEqual([
    ["critical", "src/a.js", 10],
    ["critical", "src/z.py", 2],
    ["high", "src/m.go", 7],
    ["low", "src/a.js", 40],
  ]);
});

test("file sort groups by path for line-by-line review", () => {
  expect(sortFindings(SORTABLE, "file").map(f => `${f.filePath}:${f.line}`)).toEqual([
    "src/a.js:10",
    "src/a.js:40",
    "src/m.go:7",
    "src/z.py:2",
  ]);
});

test("rule sort groups same-rule findings together, worst severity first within a rule", () => {
  expect(sortFindings(SORTABLE, "rule").map(f => f.ruleId)).toEqual([
    "go-weak-rand",
    "js-eval",
    "js-eval",
    "py-exec",
  ]);
});

test("an unmapped severity sorts last rather than crashing", () => {
  const odd = [...SORTABLE, ordered({ severity: "bogus" as Severity, ruleId: "x", filePath: "x", line: 1, column: 1 })];
  const sorted = sortFindings(odd, "severity");
  expect(sorted[sorted.length - 1]?.severity).toBe("bogus");
});

test("sorting does not mutate the input list", () => {
  const input = [...SORTABLE];
  sortFindings(SORTABLE, "file");
  expect(SORTABLE.map(f => f.line)).toEqual(input.map(f => f.line));
});
