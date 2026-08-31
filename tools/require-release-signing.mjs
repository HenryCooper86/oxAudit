#!/usr/bin/env node

import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const REQUIRED_BY_PLATFORM = Object.freeze({
  linux: Object.freeze([]),
  macos: Object.freeze([
    "APPLE_CERTIFICATE",
    "APPLE_CERTIFICATE_PASSWORD",
    "APPLE_SIGNING_IDENTITY",
    "APPLE_ID",
    "APPLE_PASSWORD",
    "APPLE_TEAM_ID",
  ]),
  windows: Object.freeze(["WINDOWS_CERTIFICATE", "WINDOWS_CERTIFICATE_PASSWORD"]),
});

function normalizePlatform(platform) {
  switch (String(platform).trim().toLowerCase()) {
    case "linux":
      return "linux";
    case "darwin":
    case "macos":
      return "macos";
    case "win32":
    case "windows":
      return "windows";
    default:
      throw new Error(`unsupported release platform: ${platform}`);
  }
}

export function requiredSigningEnvironment(platform) {
  return [...REQUIRED_BY_PLATFORM[normalizePlatform(platform)]];
}

export function missingSigningEnvironment(platform, environment = process.env) {
  return requiredSigningEnvironment(platform).filter((name) => {
    const value = environment[name];
    return typeof value !== "string" || value.trim().length === 0;
  });
}

function main() {
  const platform = process.argv[2];
  if (!platform) {
    console.error("usage: node tools/require-release-signing.mjs <Linux|macOS|Windows>");
    process.exitCode = 2;
    return;
  }

  let missing;
  try {
    missing = missingSigningEnvironment(platform);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 2;
    return;
  }

  if (missing.length > 0) {
    console.error(`release signing is incomplete; missing: ${missing.join(", ")}`);
    process.exitCode = 1;
    return;
  }

  console.log(`release signing preflight passed for ${platform}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main();
}
