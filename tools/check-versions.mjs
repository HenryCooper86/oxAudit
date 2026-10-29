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

if (problems.length > 0) {
  console.error("Version declarations have drifted:\n");
  for (const problem of problems) console.error(`  - ${problem}`);
  console.error("");
  process.exit(1);
}

console.log(
  `Version declarations agree on ${cargoVersion}; Dockerfile and rust-toolchain.toml agree on Rust ${toolchainChannel}.`,
);
