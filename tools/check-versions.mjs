#!/usr/bin/env node
/**
 * Guards the single-source-of-truth rule for oxAudit's version number.
 *
 *   src-tauri/Cargo.toml   [package] version   <- authoritative
 *   package.json           version             <- must match
 *   src-tauri/tauri.conf.json                  <- must NOT declare a version
 *                                                 (Tauri v2 falls back to Cargo.toml)
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

if (problems.length > 0) {
  console.error("Version declarations have drifted:\n");
  for (const problem of problems) console.error(`  - ${problem}`);
  console.error("");
  process.exit(1);
}

console.log(`Version declarations agree on ${cargoVersion}.`);
