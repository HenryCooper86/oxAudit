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
    /cargo install cargo-cyclonedx --version 0\.5\.10 --locked/,
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

test("a release needs no configured secret, and minisign signs only when its key exists", () => {
  // Provenance and keyless Sigstore signatures come from the run's own
  // identity, so their steps carry no condition.
  assert.match(releaseWorkflow, /- uses: actions\/attest-build-provenance@[0-9a-f]{40}[^\n]*\n\s+with:/);
  assert.match(
    releaseWorkflow,
    /- name: Sign the CLI binaries and checksums keylessly\n\s+env:/,
  );
  // minisign depends on a stored key: skipped, not failed, without it.
  assert.match(
    releaseWorkflow,
    /MINISIGN_CONFIGURED: \$\{\{ secrets\.MINISIGN_PRIVATE_KEY != '' \}\}/,
  );
  assert.match(
    releaseWorkflow,
    /- name: Sign the CLI binaries and checksums with minisign\n\s+if: env\.MINISIGN_CONFIGURED == 'true'/,
  );
  // The key reaches exactly one step.
  assert.equal(releaseWorkflow.match(/secrets\.MINISIGN_PRIVATE_KEY \}\}/g)?.length, 1);
  // The notes say which case a release is, so a missing .minisig is not
  // mistaken for a removed one.
  assert.match(releaseWorkflow, /This release carries no minisign signatures/);
  assert.match(releaseWorkflow, /They are signed with minisign as well/);
});

test("a refused container push does not block the release, and everything else does", () => {
  const publish = releaseWorkflow.split("\n  publish:\n")[1] ?? "";
  const condition = publish.split("runs-on:")[0];
  for (const need of ["bundle-linux", "bundle-cli", "sbom"]) {
    assert.match(condition, new RegExp(`needs\\.${need}\\.result == 'success'`), need);
  }
  assert.match(condition, /needs\.bundle-desktop\.result != 'failure'/);
  assert.doesNotMatch(condition, /needs\.container/);
  assert.doesNotMatch(condition, /!failure\(\)/);
  assert.match(condition, /!cancelled\(\)/);
  assert.match(condition, /startsWith\(github\.ref, 'refs\/tags\/v'\) && !inputs\.dry_run/);
  // The notes state the absence instead of staying silent about it.
  assert.match(releaseWorkflow, /This release has no container image/);
});

test("CI-installed Rust security tools use exact versions", () => {
  assert.match(securityWorkflow, /cargo install cargo-deny --version 0\.20\.2 --locked/);
  assert.match(securityWorkflow, /cargo install cargo-fuzz --version 0\.13\.2 --locked/);
});

test("self-scan excludes the intentionally vulnerable benchmark corpus", async () => {
  // The exclusion lives in the repository's own project config, which the
  // self-scan reads; the workflow must not opt out of it.
  const config = await readFile(new URL("../.oxaudit/config.toml", import.meta.url), "utf8");
  const ignored = config.match(/^ignore_dirs\s*=\s*\[([^\]]*)\]/m)?.[1] ?? "";
  assert.match(ignored, /"benchmarks"/);
  assert.doesNotMatch(selfScanWorkflow, /--no-config/);
});
