#!/usr/bin/env node
/**
 * Every GitHub Action must be pinned to a full commit SHA.
 *
 * SECURITY.md states this as a property of the project, and until now nothing
 * checked it. A tag is a moving reference: whoever controls an action's
 * repository can repoint it at different code, and these workflows hold the
 * signing keys, publish releases, and mint provenance attestations. An action
 * referenced by tag is a standing invitation to have all three taken.
 *
 * The mistake this exists to catch is not malice but drift — a new step added
 * with `@v4` because that is what the documentation shows, in a file where
 * every other line is a SHA.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const WORKFLOWS = ".github/workflows";
const FULL_SHA = /^[0-9a-f]{40}$/;

const problems = [];
let checked = 0;

for (const file of readdirSync(WORKFLOWS).filter((name) => name.endsWith(".yml"))) {
  const path = join(WORKFLOWS, file);
  const lines = readFileSync(path, "utf8").split("\n");

  lines.forEach((line, index) => {
    const match = line.match(/^\s*(?:-\s*)?uses:\s*(\S+)/);
    if (!match) return;
    const reference = match[1];

    // A local action (./path) or a reusable workflow in this repo has no
    // third party to trust.
    if (reference.startsWith("./")) return;

    checked += 1;
    const [, pinned] = reference.split("@");
    const where = `${path}:${index + 1}`;

    if (!pinned) {
      problems.push(`${where}: \`${reference}\` names no version at all.`);
    } else if (!FULL_SHA.test(pinned)) {
      problems.push(
        `${where}: \`${reference}\` is pinned to a tag or branch, not a commit SHA. ` +
          `Resolve it with:\n      gh api repos/${reference.split("@")[0].split("/").slice(0, 2).join("/")}` +
          `/git/ref/tags/${pinned} --jq .object.sha`,
      );
    }
  });
}

if (checked === 0) {
  console.error("No action references found — this check is not doing anything.");
  process.exit(1);
}

if (problems.length > 0) {
  console.error("Actions must be pinned to a full commit SHA:\n");
  for (const problem of problems) console.error(`  - ${problem}`);
  console.error(
    "\nA tag can be repointed by whoever controls the action. These workflows " +
      "hold the signing keys.\n",
  );
  process.exit(1);
}

console.log(`All ${checked} action references are pinned to a commit SHA.`);
