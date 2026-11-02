#!/usr/bin/env node
/**
 * Guards the single-source-of-truth rule for oxAudit's version number.
 *
 *   src-tauri/Cargo.toml   [package] version   <- authoritative
 *   package.json           version             <- must match
 *   src-tauri/tauri.conf.json                  <- must NOT declare a version
 *                                                 (Tauri v2 falls back to Cargo.toml)
 *   editors/vscode/package.json version        <- must match (released together)
 *
 * and for the Rust toolchain:
 *
 *   rust-toolchain.toml    [toolchain] channel <- authoritative
 *   Dockerfile             ARG RUST_IMAGE      <- rust:<channel>[-variant]
 *
 * and for the published release the documentation points users at:
 *
 *   CHANGELOG.md  "Published releases are …" <- authoritative (its last entry)
 *   README.md, docs/getting-started.md, examples/ci/oxaudit.yml, and the
 *   README's composite-Action example                <- must name it
 *   docs/cli.md   "(`oxaudit X`)" help header      <- must match Cargo.toml
 *
 * Run by CI on every push. Exits non-zero with an actionable message when the
 * declarations drift, which is the failure this file exists to prevent.
 */
import { readFileSync } from "node:fs";

const problems = [];

/** Read `version` from the `[package]` table only — crates have their own. */
function cargoPackageVersion(path) {
  const text = readFileSync(path, "utf8");
  const packageTable = text.split(/^\[/m).find((section) => section.startsWith("package]"));
  if (!packageTable) return null;
  const match = packageTable.match(/^\s*version\s*=\s*"([^"]+)"/m);
  return match ? match[1] : null;
}

const cargoVersion = cargoPackageVersion("src-tauri/Cargo.toml");
if (!cargoVersion) {
  problems.push("src-tauri/Cargo.toml: no [package] version found.");
}

// The package builds two binaries — the desktop app and the CLI. Without
// `default-run`, Tauri bundled the CLI as the app's executable, so the .app
// launched the command line and exited without ever opening a window. The
// build succeeds either way, which is why nothing else catches it.
if (!/^default-run\s*=\s*"oxaudit"/m.test(readFileSync("src-tauri/Cargo.toml", "utf8"))) {
  problems.push(
    'src-tauri/Cargo.toml must set `default-run = "oxaudit"` in [package], or the ' +
      "bundled desktop app will run oxaudit-cli and show no window.",
  );
}

const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
if (packageJson.version !== cargoVersion) {
  problems.push(
    `package.json declares ${packageJson.version}, but src-tauri/Cargo.toml declares ` +
      `${cargoVersion}. Cargo.toml is authoritative — set package.json to ${cargoVersion}.`,
  );
}

const tauriConf = JSON.parse(readFileSync("src-tauri/tauri.conf.json", "utf8"));

if (Object.hasOwn(tauriConf, "version")) {
  problems.push(
    "src-tauri/tauri.conf.json declares its own version. Remove the key so the bundle " +
      "version follows src-tauri/Cargo.toml.",
  );
}

// The VS Code extension has been bumped in the same commit as every release
// since 0.2.0; a release that forgets it ships an extension claiming the
// previous version.
const vscodePackage = JSON.parse(readFileSync("editors/vscode/package.json", "utf8"));
if (vscodePackage.version !== cargoVersion) {
  problems.push(
    `editors/vscode/package.json declares ${vscodePackage.version}, but src-tauri/Cargo.toml ` +
      `declares ${cargoVersion}. The extension is released with the app — set it to ${cargoVersion}.`,
  );
}

// The container image compiles with whatever Rust its builder image carries,
// not with rust-toolchain.toml, so the two pins drift silently: CI gates
// clippy and tests on one compiler and the published image ships another.
const toolchainMatch = readFileSync("rust-toolchain.toml", "utf8").match(
  /^\s*channel\s*=\s*"([^"]+)"/m,
);
const toolchainChannel = toolchainMatch ? toolchainMatch[1] : null;
if (!toolchainChannel) {
  problems.push("rust-toolchain.toml: no [toolchain] channel found.");
}
const rustImageMatch = readFileSync("Dockerfile", "utf8").match(
  /^\s*ARG\s+RUST_IMAGE\s*=\s*rust:([^\s-]+)(?:-\S*)?\s*$/m,
);
const rustImageVersion = rustImageMatch ? rustImageMatch[1] : null;
if (!rustImageVersion) {
  problems.push("Dockerfile: no `ARG RUST_IMAGE=rust:<version>` found.");
} else if (toolchainChannel && rustImageVersion !== toolchainChannel) {
  problems.push(
    `Dockerfile builds with rust:${rustImageVersion}, but rust-toolchain.toml pins ` +
      `${toolchainChannel}. Set RUST_IMAGE to rust:${toolchainChannel}-<variant>.`,
  );
}

// The docs name the latest *published* release, which is not the version on
// main: a release is prepared, tagged and published before the docs move.
// The changelog preamble's list of published releases is the one place that
// is edited when a release goes out; every pointer below must follow it.
const changelog = readFileSync("CHANGELOG.md", "utf8");
// The sentence ends at the first full stop followed by whitespace; the
// version numbers' own dots are followed by digits.
const publishedList = changelog.match(/Published releases are ([\s\S]*?)\.(?:\s|$)/);
const published = publishedList
  ? [...publishedList[1].matchAll(/v(\d+\.\d+\.\d+)/g)].map((match) => match[1])
  : [];
const latestPublished = published.at(-1) ?? null;
if (!latestPublished) {
  problems.push('CHANGELOG.md: no "Published releases are v…" sentence found in the preamble.');
} else {
  const pointers = [
    ["README.md", /\[latest release\]\([^)]*\)\s*\n\s*— \[v(\d+\.\d+\.\d+)\]/, "its latest-release link"],
    ["README.md", /^\s*version: v(\d+\.\d+\.\d+)\s+# release tag of the CLI/m, "its composite-Action example"],
    ["README.md", /installs the published v(\d+\.\d+\.\d+) Linux CLI/, "its consumer-workflow summary"],
    ["docs/getting-started.md", /\[latest release\]\([^)]*\)\s*\n\s*— \[v(\d+\.\d+\.\d+)\]/, "its latest-release link"],
    ["docs/getting-started.md", /against published v(\d+\.\d+\.\d+) \(/, "its platform-matrix check"],
    ["examples/ci/oxaudit.yml", /^\s*OXAUDIT_TOOL_VERSION: v(\d+\.\d+\.\d+)\s*$/m, "OXAUDIT_TOOL_VERSION"],
  ];
  for (const [file, pattern, what] of pointers) {
    const match = readFileSync(file, "utf8").match(pattern);
    if (!match) {
      problems.push(`${file}: ${what} was not found; tools/check-versions.mjs expects it.`);
    } else if (match[1] !== latestPublished) {
      problems.push(
        `${file}: ${what} names v${match[1]}, but CHANGELOG.md lists v${latestPublished} as the ` +
          `latest published release. Update it (and its pinned commit/digest) once that release is verified.`,
      );
    }
  }
}

const cliHeader = readFileSync("docs/cli.md", "utf8").match(/\(`oxaudit (\d+\.\d+\.\d+)`\)/);
if (!cliHeader) {
  problems.push("docs/cli.md: no (`oxaudit X.Y.Z`) --help header found.");
} else if (cargoVersion && cliHeader[1] !== cargoVersion) {
  problems.push(
    `docs/cli.md says it was taken from oxaudit ${cliHeader[1]} --help, but src-tauri/Cargo.toml ` +
      `declares ${cargoVersion}. Regenerate it from the current CLI's --help.`,
  );
}

if (problems.length > 0) {
  console.error("Version declarations have drifted:\n");
  for (const problem of problems) console.error(`  - ${problem}`);
  console.error("");
  process.exit(1);
}

console.log(
  `Version declarations agree on ${cargoVersion}; docs point at published v${latestPublished}; ` +
    `Dockerfile and rust-toolchain.toml agree on Rust ${toolchainChannel}.`,
);
