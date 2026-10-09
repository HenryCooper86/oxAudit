import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

const counts = (tp: number, fp: number, tn: number, fn: number) => ({ truePositives: tp, falsePositives: fp, trueNegatives: tn, falseNegatives: fn });
const envelope = () => ({ schemaVersion: 1, provenance: {
  benchmarkCommit: "550021e915c06cbcf994d97bc258128b78d890db", evaluator: "owasp-java-cwe-v1",
  expectationsSha256: "a".repeat(64), toolCommit: "b".repeat(40), cliSha256: "c".repeat(64), measuredAt: "2026-10-09T00:00:00.000Z",
}, report: { suite: "OWASP Benchmark 1.2", cases: 24, runtimeMs: 10,
  coveredTotals: counts(8, 2, 8, 2), uncoveredTotals: counts(0, 0, 2, 2), categories: [
    { category: "cmdi", cwe: 78, covered: true, ...counts(8, 2, 8, 2) },
    { category: "httponly", cwe: 1004, covered: false, ...counts(0, 0, 2, 2) },
  ] }, thresholds: { maxPrecisionDrop: 0.005, maxRecallDrop: 0.005, maxFalsePositiveRateIncrease: 0.005, maxYoudenDrop: 0.01 } });
async function compare(change: (result: ReturnType<typeof envelope>, baseline: ReturnType<typeof envelope>) => void = () => {}, repeat = false) {
  const owned = await mkdtemp(path.join(tmpdir(), "oxaudit-quality-test-"));
  try {
    const baseline = envelope(), result = envelope(); change(result, baseline);
    await writeFile(path.join(owned, "baseline.json"), JSON.stringify(baseline));
    await writeFile(path.join(owned, "result.json"), JSON.stringify(result));
    const args = ["tools/compare-quality-benchmark.mjs", "--result", path.join(owned, "result.json"), "--baseline", path.join(owned, "baseline.json"), "--output", path.join(owned, "artifacts")];
    const processResult = spawnSync(process.execPath, args, { encoding: "utf8" });
    const repeatedResult = repeat ? spawnSync(process.execPath, args, { encoding: "utf8" }) : undefined;
    let comparison;
    try { comparison = JSON.parse(await readFile(path.join(owned, "artifacts/comparison.json"), "utf8")); } catch { /* invalid contracts must not yield a passing receipt */ }
    let category;
    try { category = JSON.parse(await readFile(path.join(owned, "artifacts/categories/cmdi.json"), "utf8")); } catch { /* missing implementation */ }
    return { ...processResult, comparison, category, repeatedResult };
  } finally { await rm(owned, { recursive: true, force: true }); }
}
test("compatible category comparison retains explicit covered and uncovered populations", async () => {
  const result = await compare();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.comparison.status, "passed");
  assert.deepEqual(result.comparison.population, { allCases: 24, coveredCases: 20, uncoveredCases: 4, baselineCoveredCases: 20 });
  assert.equal(result.category.current.metrics.precision, 0.8);
  assert.equal(result.category.current.metrics.recall, 0.8);
  assert.equal(result.category.current.metrics.falsePositiveRate, 0.2);
  assert.ok(Math.abs(result.category.current.metrics.youdenIndex - 0.6) < 1e-12);
  assert.deepEqual(result.category.deltas, { precision: 0, recall: 0, falsePositiveRate: 0, youdenIndex: 0 });
});
test("a category recall regression fails even when another category improves", async () => {
  const result = await compare((current, baseline) => {
    current.report.categories.push({ category: "sqli", cwe: 89, covered: true, ...counts(10, 0, 10, 0) });
    baseline.report.categories.push({ category: "sqli", cwe: 89, covered: true, ...counts(0, 0, 10, 10) });
    current.report.categories[0].truePositives = 7; current.report.categories[0].falseNegatives = 3;
    current.report.cases = baseline.report.cases = 44;
    current.report.coveredTotals = counts(17, 2, 18, 3); baseline.report.coveredTotals = counts(8, 2, 18, 12);
  });
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.comparison.status, "regressed");
  assert.ok(result.category.regressions.some((item: { metric: string }) => item.metric === "recall"));
});
for (const [name, change] of [
  ["changed pin", (r: ReturnType<typeof envelope>) => { r.provenance.benchmarkCommit = "d".repeat(40); }],
  ["changed ground truth", (r: ReturnType<typeof envelope>) => { r.provenance.expectationsSha256 = "d".repeat(64); }],
  ["missing category", (r: ReturnType<typeof envelope>) => { r.report.categories.pop(); }],
  ["changed population", (r: ReturnType<typeof envelope>) => { r.report.categories[0].falseNegatives++; r.report.coveredTotals.falseNegatives++; r.report.cases++; }],
  ["incorrect totals", (r: ReturnType<typeof envelope>) => { r.report.coveredTotals.truePositives++; }],
  ["duplicate category", (r: ReturnType<typeof envelope>) => { r.report.categories.push(r.report.categories[0]); }],
  ["negative threshold", (_r: ReturnType<typeof envelope>, b: ReturnType<typeof envelope>) => { b.thresholds.maxRecallDrop = -1; }],
] as const) test(`comparison refuses ${name}`, async () => {
  const result = await compare(change);
  assert.equal(result.status, 2, result.stderr);
  assert.notEqual(result.comparison?.status, "passed");
});
test("loss of rule coverage fails with evidence, including its original population", async () => {
  const result = await compare((r) => { r.report.categories[0].covered = false; r.report.coveredTotals = counts(0, 0, 0, 0); r.report.uncoveredTotals = counts(8, 2, 10, 4); });
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.category.status, "coverage-lost");
  assert.equal(result.comparison.population.baselineCoveredCases, 20);
});
test("an undefined precision cannot hide loss of all detections", async () => {
  const result = await compare((r) => { r.report.categories[0] = { category: "cmdi", cwe: 78, covered: true, ...counts(0, 0, 10, 10) }; r.report.coveredTotals = counts(0, 0, 10, 10); });
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.category.current.metrics.precision, null);
});
test("false-positive growth is gated per category even with unchanged recall", async () => {
  const result = await compare((r) => { r.report.categories[0].falsePositives = 3; r.report.categories[0].trueNegatives = 7; r.report.coveredTotals = counts(8, 3, 7, 2); });
  assert.equal(result.status, 1, result.stderr);
  assert.ok(result.category.regressions.some((item: { metric: string }) => item.metric === "falsePositiveRate"));
});
test("new rule coverage reports the larger population while retaining the baseline comparison population", async () => {
  const result = await compare((r) => { r.report.categories[1].covered = true; r.report.coveredTotals = counts(8, 2, 10, 4); r.report.uncoveredTotals = counts(0, 0, 0, 0); });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.comparison.population, { allCases: 24, coveredCases: 24, uncoveredCases: 0, baselineCoveredCases: 20 });
  assert.equal(result.comparison.baselineCoveredPopulationCurrentMetrics.recall, 0.8);
  assert.equal(result.comparison.categories.find((item: { category: string }) => item.category === "httponly").status, "coverage-added");
});
test("comparison refuses reuse of an artifact directory so old receipts cannot silently become a new run", async () => {
  const result = await compare(() => {}, true);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.repeatedResult?.status, 2, result.repeatedResult?.stderr);
});
