#!/usr/bin/env node
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const countKeys = ["truePositives", "falsePositives", "trueNegatives", "falseNegatives"];
const limits = { precision: "maxPrecisionDrop", recall: "maxRecallDrop", falsePositiveRate: "maxFalsePositiveRateIncrease", youdenIndex: "maxYoudenDrop" };
const cases = (row) => countKeys.reduce((sum, key) => sum + row[key], 0);
const counts = (rows) => Object.fromEntries(countKeys.map((key) => [key, rows.reduce((sum, row) => sum + row[key], 0)]));
function validateCounts(row) {
  for (const key of countKeys) assert.ok(Number.isSafeInteger(row?.[key]) && row[key] >= 0, `${key} must be a nonnegative integer`);
  assert.ok(Number.isSafeInteger(cases(row)), "population exceeds safe integer range");
}
export function validateQualityEnvelope(value) {
  assert.equal(value?.schemaVersion, 1, "Expected quality envelope schemaVersion 1");
  const p = value.provenance;
  assert.match(p?.benchmarkCommit ?? "", /^[0-9a-f]{40}$/, "Missing pinned benchmark commit");
  assert.match(p?.toolCommit ?? "", /^[0-9a-f]{40}$/, "Missing tool commit provenance");
  for (const key of ["expectationsSha256", "cliSha256"]) assert.match(p?.[key] ?? "", /^[0-9a-f]{64}$/, `Missing ${key}`);
  assert.equal(p?.evaluator, "owasp-java-cwe-v1", "Unsupported benchmark evaluator");
  assert.ok(typeof p.measuredAt === "string" && Number.isFinite(Date.parse(p.measuredAt)), "Missing measurement date");
  const r = value.report;
  assert.ok(typeof r?.suite === "string" && r.suite.length > 0, "Missing suite");
  assert.ok(Number.isSafeInteger(r?.cases) && r.cases > 0, "Invalid case count");
  assert.ok(Number.isFinite(r?.runtimeMs) && r.runtimeMs >= 0, "Invalid runtime");
  assert.ok(Array.isArray(r?.categories) && r.categories.length > 0, "Missing per-category results");
  const names = new Set();
  for (const row of r.categories) {
    assert.match(row.category ?? "", /^[a-zA-Z0-9_-]+$/, "Invalid category name");
    assert.ok(!names.has(row.category), `Duplicate category ${row.category}`); names.add(row.category);
    assert.ok(Number.isSafeInteger(row.cwe) && row.cwe > 0 && typeof row.covered === "boolean", "Invalid category coverage/CWE");
    validateCounts(row); assert.ok(cases(row) > 0, "Empty category population");
  }
  validateCounts(r.coveredTotals); validateCounts(r.uncoveredTotals);
  assert.deepEqual(r.coveredTotals, counts(r.categories.filter((row) => row.covered)), "Covered totals disagree with categories");
  assert.deepEqual(r.uncoveredTotals, counts(r.categories.filter((row) => !row.covered)), "Uncovered totals disagree with categories");
  assert.equal(r.cases, cases(r.coveredTotals) + cases(r.uncoveredTotals), "Total cases disagree with categories");
  return value;
}
function metrics(c) {
  const divide = (numerator, denominator) => denominator ? numerator / denominator : null;
  const recall = divide(c.truePositives, c.truePositives + c.falseNegatives);
  const falsePositiveRate = divide(c.falsePositives, c.falsePositives + c.trueNegatives);
  return { precision: divide(c.truePositives, c.truePositives + c.falsePositives), recall, falsePositiveRate,
    youdenIndex: recall === null || falsePositiveRate === null ? null : recall - falsePositiveRate };
}
export async function compareQuality({ result, baseline, output }) {
  validateQualityEnvelope(result); validateQualityEnvelope(baseline);
  for (const key of ["benchmarkCommit", "expectationsSha256", "evaluator"]) assert.equal(result.provenance[key], baseline.provenance[key], `Incompatible ${key}`);
  assert.equal(result.report.suite, baseline.report.suite, "Incompatible suite");
  const thresholds = baseline.thresholds;
  for (const key of Object.values(limits)) assert.ok(Number.isFinite(thresholds?.[key]) && thresholds[key] >= 0 && thresholds[key] <= 1, `Invalid threshold ${key}`);
  const previous = new Map(baseline.report.categories.map((row) => [row.category, row]));
  assert.equal(result.report.categories.length, previous.size, "Category set changed; establish a reviewed baseline");
  const comparisons = result.report.categories.map((current) => {
    const prior = previous.get(current.category);
    assert.ok(prior, `New category ${current.category}; establish a reviewed baseline`);
    assert.equal(current.cwe, prior.cwe, `CWE changed for ${current.category}`);
    assert.equal(current.truePositives + current.falseNegatives, prior.truePositives + prior.falseNegatives, `Vulnerable population changed for ${current.category}`);
    assert.equal(current.falsePositives + current.trueNegatives, prior.falsePositives + prior.trueNegatives, `Safe population changed for ${current.category}`);
    const a = metrics(current), b = metrics(prior), regressions = [];
    const deltas = Object.fromEntries(Object.keys(limits).map((metric) => [metric, a[metric] === null || b[metric] === null ? null : a[metric] - b[metric]]));
    if (prior.covered) for (const [metric, key] of Object.entries(limits)) {
      if (b[metric] === null) continue;
      const deterioration = a[metric] === null ? null : metric === "falsePositiveRate" ? a[metric] - b[metric] : b[metric] - a[metric];
      if (deterioration === null || deterioration > thresholds[key] + 1e-12) regressions.push({ metric, baseline: b[metric], current: a[metric], tolerance: thresholds[key] });
    }
    const status = prior.covered && !current.covered ? "coverage-lost" : regressions.length ? "regressed" : !prior.covered && current.covered ? "coverage-added" : current.covered ? "passed" : "uncovered";
    return { category: current.category, cwe: current.cwe, status, population: { vulnerable: current.truePositives + current.falseNegatives, safe: current.falsePositives + current.trueNegatives },
      baseline: { ...prior, metrics: b }, current: { ...current, metrics: a }, deltas, regressions };
  });
  const summary = { schemaVersion: 1, status: comparisons.some((c) => ["coverage-lost", "regressed"].includes(c.status)) ? "regressed" : "passed",
    provenance: result.provenance, baselineProvenance: baseline.provenance, thresholds,
    population: { allCases: result.report.cases, coveredCases: cases(result.report.coveredTotals), uncoveredCases: cases(result.report.uncoveredTotals), baselineCoveredCases: cases(baseline.report.coveredTotals) },
    // The historical covered population remains fixed even if new categories gain rules.
    baselineCoveredPopulationCurrentMetrics: metrics(counts(result.report.categories.filter((row) => previous.get(row.category).covered))),
    coveredMetrics: metrics(result.report.coveredTotals), uncoveredMetrics: metrics(result.report.uncoveredTotals), categories: comparisons };
  await mkdir(path.dirname(path.resolve(output)), { recursive: true }); await mkdir(output);
  await mkdir(path.join(output, "categories"));
  for (const category of comparisons) await writeFile(path.join(output, "categories", `${category.category}.json`), JSON.stringify(category, null, 2) + "\n");
  await writeFile(path.join(output, "comparison.json"), JSON.stringify(summary, null, 2) + "\n");
  return summary;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2), options = {};
    assert.equal(args.length, 6, "Usage: compare-quality-benchmark.mjs --result FILE --baseline FILE --output DIR");
    for (let i = 0; i < args.length; i += 2) { assert.ok(["--result", "--baseline", "--output"].includes(args[i]) && !options[args[i]], "Invalid/duplicate option"); options[args[i]] = args[i + 1]; }
    assert.ok(options["--result"] && options["--baseline"] && options["--output"], "Missing options");
    const summary = await compareQuality({ result: JSON.parse(await readFile(options["--result"], "utf8")), baseline: JSON.parse(await readFile(options["--baseline"], "utf8")), output: options["--output"] });
    console.log(`${summary.status}: ${summary.population.coveredCases}/${summary.population.allCases} cases in covered categories; category artifacts retained`);
    process.exitCode = summary.status === "passed" ? 0 : 1;
  } catch (error) { console.error(`Quality comparison refused: ${error.message}`); process.exitCode = 2; }
}
