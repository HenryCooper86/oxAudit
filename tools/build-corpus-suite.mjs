#!/usr/bin/env node
/**
 * Regenerates benchmarks/corpus/suite.json from the fixture files on disk.
 *
 * The corpus is the only thing standing between "our scanner is accurate" and
 * an unverifiable claim, so adding a case has to be cheap. It costs one file:
 *
 *     <rule-id>__positive__<slug>.<ext>    that rule must fire at least once
 *     <rule-id>__negative__<slug>.<ext>    that rule must not fire at all
 *
 * Then `node tools/build-corpus-suite.mjs` rewrites the manifest with a SHA-256
 * per fixture, so a fixture cannot drift out from under a recorded expectation
 * without the hash changing.
 *
 * Pass --check to verify the committed manifest matches the files without
 * writing anything; CI uses that so a fixture edited without a rebuild fails
 * loudly rather than silently changing what the numbers mean.
 */
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync, statSync } from "node:fs";
import { join, relative, extname } from "node:path";

const CORPUS = "benchmarks/corpus";
const MANIFEST = join(CORPUS, "suite.json");

// These fixtures intentionally exercise both a provider-specific detector
// and a generic secret detector. Keep both expectations in generated output.
const ADDITIONAL_EXPECTATIONS = {
  "secrets/datadog-api-key__positive__agent.yaml": "generic-api-key",
  "secrets/figma-token__positive__export.js": "generic-api-key",
  "secrets/grafana-service-account-token__positive__dashboard.yaml": "generic-api-key",
  "secrets/linear-api-key__positive__sync.py": "generic-api-key",
  "secrets/newrelic-api-key__positive__collector.yaml": "generic-api-key",
  "secrets/plaid-api-key__positive__bank_sync.py": "generic-password",
  "secrets/postman-api-key__positive__collection.js": "generic-api-key",
  "secrets/sentry-token__positive__client.js": "generic-api-key",
  "secrets/square-access-token__positive__checkout.js": "generic-api-key",
};

/** Language for a fixture, from its extension. Drives which rules apply. */
const LANGUAGE_BY_EXTENSION = {
  ".js": "javascript",
  ".jsx": "javascript",
  ".ts": "javascript",
  ".tsx": "javascript",
  ".py": "python",
  ".java": "java",
  ".go": "go",
  ".c": "c",
  ".h": "c",
  ".cpp": "cpp",
  ".rs": "rust",
  ".php": "php",
  ".rb": "ruby",
  ".cs": "csharp",
  ".kt": "kotlin",
  ".kts": "kotlin",
  ".swift": "swift",
  ".tf": "terraform",
  ".yaml": "yaml",
  ".yml": "yaml",
  ".Dockerfile": "dockerfile",
};

/**
 * Language for a fixture path.
 *
 * Extensions decide most files, but a workflow file is YAML whose rules are
 * workflow rules; fixtures kept under `source/github-actions/` are classified
 * by their directory rather than their extension.
 */
function languageFor(path) {
  if (path.includes("/github-actions/")) return "github-actions";
  return LANGUAGE_BY_EXTENSION[extname(path)] ?? null;
}

function walk(directory) {
  const found = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) found.push(...walk(path));
    else if (entry !== "suite.json") found.push(path);
  }
  return found.sort();
}

function parseFixtureName(path) {
  const name = path.split("/").pop() ?? "";
  const base = name.slice(0, name.length - extname(name).length);
  const parts = base.split("__");
  if (parts.length !== 3) {
    throw new Error(
      `${path}: expected <rule-id>__<positive|negative>__<slug>, got "${base}"`,
    );
  }
  const [ruleId, polarity, slug] = parts;
  if (polarity !== "positive" && polarity !== "negative") {
    throw new Error(`${path}: polarity must be positive or negative, got "${polarity}"`);
  }
  return { ruleId, polarity, slug };
}

/**
 * Which scanner families a fixture exercises.
 *
 * Secret rules and source-pattern rules are separate engines; running both over
 * every fixture would credit a rule for a hit another engine produced.
 */
function familyFor(path) {
  return path.includes("/secrets/") ? "secret" : "source-pattern";
}

const fixtures = walk(CORPUS).map((path) => {
  const { ruleId, polarity, slug } = parseFixtureName(path);
  const content = readFileSync(path);
  const inputPath = relative(CORPUS, path).replaceAll("\\", "/");
  const additionalRule = ADDITIONAL_EXPECTATIONS[inputPath];
  return {
    id: `${ruleId}.${polarity}.${slug.replaceAll("_", "-")}`,
    inputPath,
    inputSha256: createHash("sha256").update(content).digest("hex"),
    language: languageFor(path),
    scannerFamilies: [familyFor(path)],
    ruleId,
    // A positive asserts the rule fires here; a negative asserts it does not.
    // Both are load-bearing: a corpus of only positives measures recall and
    // says nothing about the false positives that make a scanner unusable.
    expected: polarity === "positive"
      ? [
          { ruleId, minimum: 1 },
          ...(additionalRule ? [{ ruleId: additionalRule, minimum: 1 }] : []),
        ]
      : [],
    expectedAbsent: polarity === "negative" ? [{ ruleId }] : [],
  };
});

// A fixture whose extension is not in the map above still gets written, with a
// null language — and then scores as a miss for a reason that has nothing to do
// with the scanner. Twelve fixtures for three new languages did exactly that,
// and the benchmark reported it as a recall failure rather than a missing map
// entry. Fail loudly instead.
const unmapped = fixtures.filter(
  (fixture) => fixture.language === null && !fixture.inputPath.startsWith("secrets/"),
);
if (unmapped.length > 0) {
  console.error("Fixtures whose extension has no language mapping:\n");
  for (const fixture of unmapped) console.error(`  - ${fixture.inputPath}`);
  console.error(
    "\nAdd the extension to LANGUAGE_BY_EXTENSION, or these score as misses " +
      "for a reason that is not the scanner's.\n",
  );
  process.exit(1);
}

if (fixtures.length === 0) {
  console.error(`No fixtures found under ${CORPUS}.`);
  process.exit(1);
}

const duplicates = fixtures
  .map((fixture) => fixture.id)
  .filter((id, index, all) => all.indexOf(id) !== index);
if (duplicates.length > 0) {
  console.error(`Duplicate fixture ids: ${[...new Set(duplicates)].join(", ")}`);
  process.exit(1);
}

const suite = {
  schemaVersion: 1,
  id: "oxaudit.corpus",
  // Bump when expectations change meaning, not when a fixture is added.
  version: "1.0.0",
  description:
    "Paired positive and negative fixtures for oxAudit's source-pattern and secret rules. " +
    "Negatives are drawn from shapes the scanner was observed to fire on incorrectly, so the " +
    "precision figure this produces reflects real false-positive classes rather than only " +
    "cases chosen to pass.",
  provenance: {
    authors: ["oxAudit contributors"],
    source: "Repository-authored fixtures",
    license: "Apache-2.0",
    creationMethod: "authored",
  },
  counts: {
    fixtures: fixtures.length,
    positives: fixtures.filter((f) => f.expected.length > 0).length,
    negatives: fixtures.filter((f) => f.expectedAbsent.length > 0).length,
    rules: new Set(fixtures.map((f) => f.ruleId)).size,
  },
  targets: fixtures,
};

const serialized = `${JSON.stringify(suite, null, 2)}\n`;

if (process.argv.includes("--check")) {
  let committed;
  try {
    committed = readFileSync(MANIFEST, "utf8");
  } catch {
    console.error(`${MANIFEST} does not exist. Run: node tools/build-corpus-suite.mjs`);
    process.exit(1);
  }
  if (committed !== serialized) {
    console.error(
      `${MANIFEST} is out of date with the fixtures on disk.\n` +
        "A fixture was added, removed, or edited without rebuilding the manifest, so the " +
        "recorded expectations no longer describe the files being measured.\n\n" +
        "Run: node tools/build-corpus-suite.mjs",
    );
    process.exit(1);
  }
  console.log(`${MANIFEST} matches ${fixtures.length} fixtures on disk.`);
  process.exit(0);
}

writeFileSync(MANIFEST, serialized);
console.log(
  `Wrote ${MANIFEST}: ${suite.counts.fixtures} fixtures ` +
    `(${suite.counts.positives} positive, ${suite.counts.negatives} negative) ` +
    `across ${suite.counts.rules} rules.`,
);
