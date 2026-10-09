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

export const REPOSITORY = "https://github.com/OWASP-Benchmark/BenchmarkJava";
/** Pinned so a published score can be reproduced, not merely repeated. */
export const COMMIT = "550021e915c06cbcf994d97bc258128b78d890db";

function git(args, options = {}) {
  // Inherited output is deliberately visible during clone/checkout. It has no
  // captured return value, so it must not be treated as a string.
  return execFileSync("git", args, { encoding: "utf8", stdio: "pipe", ...options })?.trim() ?? "";
}

function currentCommit(target) {
  try {
    return git(["-C", target, "rev-parse", "HEAD"]);
  } catch {
    return null;
  }
}

/** Parameters support local real-Git contract tests; the CLI always uses the pin. */
export function fetchBenchmark({ repository = REPOSITORY, commit = COMMIT, target = TARGET, force = false } = {}) {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("Expected a full commit SHA");
  const current = currentCommit(target);
  if (current === commit && !force) {
    console.log(`OWASP Benchmark already at ${commit.slice(0, 12)}.`);
    return { target, commit };
  }
  if (existsSync(target)) {
    if (!force) throw new Error(`${target} is at a different commit or is not a verified checkout. Re-run with --force to replace it.`);
    rmSync(target, { recursive: true, force: true });
  }
  mkdirSync(dirname(target), { recursive: true });
  console.log(`Fetching OWASP Benchmark at ${commit.slice(0, 12)} (a few hundred MB)…`);
  // A full clone, then a checkout of the pin: the commit is not necessarily a
  // branch tip, and --depth 1 cannot fetch an arbitrary commit from a server
  // that has not enabled uploadpack.allowReachableSHA1InWant.
  git(["clone", "--quiet", repository, target], { stdio: "inherit" });
  git(["-C", target, "checkout", "--quiet", commit], { stdio: "inherit" });
  const resolved = currentCommit(target);
  if (resolved !== commit) throw new Error(`Checked out ${resolved}, expected ${commit}.`);
  return { target, commit };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.slice(2).some((arg) => arg !== "--force")) throw new Error("Usage: fetch-external-benchmark.mjs [--force]");
    fetchBenchmark({ force: process.argv.includes("--force") });
    console.log("Fetched to benchmarks/external/owasp-benchmark (GPL-2.0, not redistributed).\nScore it with:\n  cargo run --release --bin oxaudit-cli -- external-benchmark\n");
  } catch (error) { console.error(`Could not fetch the benchmark: ${error.message}`); process.exitCode = 1; }
}
