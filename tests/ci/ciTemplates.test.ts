import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const exec = promisify(execFile);
const read = (name: string) => readFile(new URL(`../../${name}`, import.meta.url), "utf8");

const templates = [
  "examples/ci/gitlab-ci.yml",
  "examples/ci/Jenkinsfile",
  "examples/ci/azure-pipelines.yml",
  "examples/ci/bitbucket-pipelines.yml",
  "examples/ci/circleci-config.yml",
];
// What the CLI accepts, per command. Kept beside the templates so a template
// cannot ask for a format its command refuses.
const formats: Record<string, string[]> = {
  scan: ["sarif", "junit", "gitlab-code-quality", "json"],
  deps: ["cyclonedx", "spdx", "sarif", "junit", "gitlab-code-quality", "gitlab-dependency-scanning", "json"],
  sca: ["json", "junit", "gitlab-code-quality", "gitlab-dependency-scanning", "text"],
};

for (const name of templates) {
  test(`${name} installs a pinned CLI and runs only known commands`, async () => {
    const text = await read(name);
    assert.match(text, /ci\/install-oxaudit\.sh/, "installs through the reviewed script");
    assert.doesNotMatch(text, /curl[^\n]*\|\s*(ba)?sh/, "never pipes a download into a shell");
    assert.doesNotMatch(text, /releases\/latest/, "never follows a moving release");
    const calls = [...text.replaceAll(/\\?\n\s+(?=--|-o )/g, " ").matchAll(/oxaudit-cli (\w+) ([^\n]*)/g)];
    assert.ok(calls.length >= 3, "scans source, components and writes an SBOM");
    for (const [, command, rest] of calls) {
      assert.ok(command in formats, `unknown command ${command}`);
      const format = rest.match(/--format (\S+)/)?.[1];
      assert.ok(format, `${command} names a format`);
      assert.ok(formats[command].includes(format), `${command} --format ${format}`);
      // A later step must not hide an earlier failed gate.
      assert.match(rest, /\|\| status=\$\?$/, `${command} records its exit code`);
    }
    assert.match(text, /exit \$status/, "fails with the worst exit code");
    assert.match(text, /sca \. --db \S+(?! --offline)/, "one online sca run stores the receipt the others reuse");
  });
}

test("the composite action only runs a listed command and passes the target after --", async () => {
  const action = await read("action/action.yml");
  assert.match(action, /scan\|deps\|sca\|image\) ;;/);
  assert.match(action, /"\$INPUT_COMMAND" \$\{extra_args\[@\]\+"\$\{extra_args\[@\]\}"\} -- "\$INPUT_TARGET"/);
  for (const body of action.split("run: |\n").slice(1).map((rest) => rest.split("\n    - name:")[0])) {
    assert.doesNotMatch(body, /\$\{\{/, "inputs reach the shell through env only");
  }
});

async function install(digest: string, body = "#!/bin/sh\necho oxaudit 9.9.9\n") {
  const root = await mkdtemp(path.join(tmpdir(), "oxaudit install "));
  const bin = path.join(root, "bin");
  await mkdir(bin);
  // A stand-in curl that writes the "release asset" to the -o path.
  const asset = path.join(root, "asset");
  await writeFile(asset, body);
  await writeFile(path.join(bin, "curl"), `#!/bin/sh
while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; url="$1"; shift; done
echo "$url" > "${root}/url"
cp "${asset}" "$out"
`);
  await chmod(path.join(bin, "curl"), 0o755);
  const script = new URL("../../examples/ci/install-oxaudit.sh", import.meta.url).pathname;
  const env = { PATH: `${bin}:${process.env.PATH}`, OXAUDIT_VERSION: "v9.9.9",
    OXAUDIT_SHA256: digest === "match" ? createHash("sha256").update(body).digest("hex") : digest };
  return { root, run: exec("sh", [script], { cwd: root, env }) };
}

test("install-oxaudit.sh installs an asset whose digest matches the pin", async () => {
  const { root, run } = await install("match");
  const { stdout } = await run;
  assert.match(stdout, /oxaudit 9\.9\.9/);
  assert.match(await readFile(path.join(root, "url"), "utf8"),
    /^https:\/\/github\.com\/HenryCooper86\/oxAudit\/releases\/download\/v9\.9\.9\/oxaudit-cli-/);
});

test("install-oxaudit.sh refuses an asset whose digest does not match", async () => {
  const { root, run } = await install("0".repeat(64));
  await assert.rejects(run);
  await assert.rejects(readFile(path.join(root, ".oxaudit-tool/oxaudit-cli")));
});

test("install-oxaudit.sh refuses to run without a pinned version and digest", async () => {
  const script = new URL("../../examples/ci/install-oxaudit.sh", import.meta.url).pathname;
  await assert.rejects(exec("sh", [script], { env: { PATH: process.env.PATH } }), /OXAUDIT_VERSION/);
});

async function glibcFloor(symbols: string, allowed: string) {
  const root = await mkdtemp(path.join(tmpdir(), "oxaudit glibc "));
  const bin = path.join(root, "bin");
  await mkdir(bin);
  await writeFile(path.join(root, "symbols.txt"), symbols);
  // A stand-in objdump that prints the fixture's dynamic symbol table.
  await writeFile(path.join(bin, "objdump"), `#!/bin/sh\ncat "${root}/symbols.txt"\n`);
  await chmod(path.join(bin, "objdump"), 0o755);
  const script = new URL("../../tools/check-glibc-floor.sh", import.meta.url).pathname;
  return exec("sh", [script, "oxaudit-cli", allowed], {
    cwd: root,
    env: { PATH: `${bin}:${process.env.PATH}` },
  });
}

const symbolTable = (...versions: string[]) =>
  versions.map((version) => `0000000000000000      DF *UND*  0000000000000000 (GLIBC_${version}) read`).join("\n") + "\n";

test("the glibc check passes a binary at or below the allowed version", async () => {
  const { stdout } = await glibcFloor(symbolTable("2.2.5", "2.17", "2.35", "2.4"), "2.35");
  assert.match(stdout, /needs glibc 2\.35 \(allowed up to 2\.35\)/);
  // Versions compare numerically: 2.4 is older than 2.35, not newer.
  await glibcFloor(symbolTable("2.4", "2.9"), "2.35");
});

test("the glibc check fails a binary that needs a newer glibc, or one it cannot read", async () => {
  await assert.rejects(glibcFloor(symbolTable("2.17", "2.39", "2.38"), "2.35"), /needs glibc 2\.39, newer than the allowed 2\.35/);
  await assert.rejects(glibcFloor("no versioned symbols here\n", "2.35"), /nothing to check/);
});
