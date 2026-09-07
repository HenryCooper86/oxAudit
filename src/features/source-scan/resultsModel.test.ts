import { expect, test } from "vitest";
import { filterFindings } from "./resultsModel";
import type { Finding } from "../../lib/types";
import type { ResultsQuery } from "./types";
const query: ResultsQuery = { view: "open", category: "all", severity: "all", scope: "all", language: "all", search: "" };
const finding = (id: string, diffStatus: Finding["diffStatus"], scope: Finding["scope"] = "production") => ({ fingerprint: id, diffStatus, scope } as Finding);
test("new since baseline intersects every review and scope view", () => {
  const findings = [finding("new", "new"), finding("old", "unchanged"), finding("test", "new", "test"), { ...finding("closed", "new"), review: { state: "acceptedRisk" } } as Finding];
  expect(filterFindings(findings, { ...query, newOnly: true }).map(f => f.fingerprint)).toEqual(["new"]);
  expect(filterFindings(findings, { ...query, view: "otherScopes", newOnly: true }).map(f => f.fingerprint)).toEqual(["test"]);
  expect(filterFindings(findings, { ...query, view: "closed", newOnly: true }).map(f => f.fingerprint)).toEqual(["closed"]);
  expect(filterFindings([finding("resolved", "resolved")], { ...query, view: "resolved", newOnly: true })).toEqual([]);
});
