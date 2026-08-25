#!/usr/bin/env node
/**
 * Fetch the OWASP Benchmark into a working directory for measurement.
 *
 * oxAudit's own corpus is written by the same people who write its rules, so
 * it can only ever answer "does it still do what we meant?". It cannot answer
 * "is it any good?" — a corpus you tuned against proves little, and the README
 * says so. The OWASP Benchmark is ground truth nobody here authored: 2,740
 * generated Java servlets, each labelled vulnerable or safe by the project
 * that generated them.
 *
 * It is NOT vendored, for two reasons that point the same way:
 *
 *   - It is GPL-2.0 and oxAudit is Apache-2.0. Redistributing it inside this
 *     repository would be a licensing problem. Fetching it locally to measure
 *     against is not.
 *   - It is 239MB, most of which is git history and build scaffolding nobody
 *     needs to read a score.
 *
 * So the harness lives here and the corpus is fetched on demand, pinned to a
 * commit so a score is reproducible rather than a snapshot of whatever HEAD
 * happened to be.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TARGET = join(ROOT, "benchmarks", "external", "owasp-benchmark");

const REPOSITORY = "https://github.com/OWASP-Benchmark/BenchmarkJava";
/** Pinned so a published score can be reproduced, not merely repeated. */
const COMMIT = "550021e915c06cbcf994d97bc258128b78d890db";

function git(args, options = {}) {
  return execFileSync("git", args, { encoding: "utf8", stdio: "pipe", ...options }).trim();
}

function currentCommit() {
  try {
    return git(["-C", TARGET, "rev-parse", "HEAD"]);
  } catch {
    return null;
  }
}

const force = process.argv.includes("--force");

if (currentCommit() === COMMIT && !force) {
  console.log(`OWASP Benchmark already at ${COMMIT.slice(0, 12)} in benchmarks/external/.`);
  process.exit(0);
}

if (existsSync(TARGET)) {
  if (!force && currentCommit() !== null) {
    console.error(
      `${TARGET} is at a different commit. Re-run with --force to replace it.`,
    );
    process.exit(1);
  }
  rmSync(TARGET, { recursive: true, force: true });
}

mkdirSync(dirname(TARGET), { recursive: true });

console.log(`Fetching OWASP Benchmark at ${COMMIT.slice(0, 12)} (a few hundred MB)…`);
try {
  // A full clone, then a checkout of the pin: the commit is not necessarily a
  // branch tip, and --depth 1 cannot fetch an arbitrary commit from a server
  // that has not enabled uploadpack.allowReachableSHA1InWant.
  git(["clone", "--quiet", REPOSITORY, TARGET], { stdio: "inherit" });
  git(["-C", TARGET, "checkout", "--quiet", COMMIT]);
} catch (error) {
  console.error(`\nCould not fetch the benchmark: ${error.message}`);
  console.error("This needs network access to github.com.");
  process.exit(1);
}

const resolved = currentCommit();
if (resolved !== COMMIT) {
  console.error(`Checked out ${resolved}, expected ${COMMIT}.`);
  process.exit(1);
}

console.log(`\nFetched to benchmarks/external/owasp-benchmark (GPL-2.0, not redistributed).`);
console.log("Score it with:\n");
console.log("  cargo run --release --bin oxaudit-cli -- external-benchmark\n");
