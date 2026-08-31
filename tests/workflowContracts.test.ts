import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const securityWorkflow = await readFile(
  new URL("../.github/workflows/security.yml", import.meta.url),
  "utf8",
);
const releaseWorkflow = await readFile(
  new URL("../.github/workflows/release.yml", import.meta.url),
  "utf8",
);
const selfScanWorkflow = await readFile(
  new URL("../.github/workflows/self-scan.yml", import.meta.url),
  "utf8",
);

test("the JavaScript dependency audit is an executable CI contract", () => {
  assert.equal(packageJson.scripts["audit:dependencies"], "npm audit --audit-level=high");
  assert.match(securityWorkflow, /npm run audit:dependencies/);
});

test("release SBOM generators use exact versions", () => {
  assert.match(
    releaseWorkflow,
    /cargo install cargo-cyclonedx --version 0\.5\.9 --locked/,
  );
  assert.match(releaseWorkflow, /@cyclonedx\/cyclonedx-npm@6\.0\.1/);
  assert.doesNotMatch(releaseWorkflow, /cyclonedx-npm@latest/);
});

test("tag bundles run the fail-closed signing preflight", () => {
  assert.match(releaseWorkflow, /Require native signing for publishable bundles/);
  assert.match(
    releaseWorkflow,
    /Require native signing for publishable bundles\n\s+if: startsWith\(github\.ref, 'refs\/tags\/v'\) && !inputs\.dry_run/,
  );
  assert.match(
    releaseWorkflow,
    /node tools\/require-release-signing\.mjs "\$\{\{ runner\.os \}\}"/,
  );
  assert.doesNotMatch(releaseWorkflow, /Producing an UNSIGNED/);
});

test("CI-installed Rust security tools use exact versions", () => {
  assert.match(securityWorkflow, /cargo install cargo-deny --version 0\.20\.2 --locked/);
  assert.match(securityWorkflow, /cargo install cargo-fuzz --version 0\.13\.2 --locked/);
});

test("self-scan excludes the intentionally vulnerable benchmark corpus", () => {
  assert.match(selfScanWorkflow, /--ignore-dir benchmarks/);
});
