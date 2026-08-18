import assert from "node:assert/strict";
import test from "node:test";
import {
  buildSourceScanRequest,
  createSourceScanOptions,
  editSourceScanOption,
  hydrateSourceScanOptions,
  resolveSourceScanOptionsUnavailable,
} from "../src/lib/sourceScanOptions";
import type { ScanSettings } from "../src/lib/types";

const savedDefaults: ScanSettings = {
  scanSecrets: false,
  scanVulnerabilities: true,
  includeGit: false,
  followSymlinks: true,
  maxFileSizeKb: 777,
  ignoredDirs: ["saved-only"],
};

test("editing one Source option before load preserves only that field while untouched defaults hydrate", () => {
  const initial = createSourceScanOptions(null);
  const edited = editSourceScanOption(initial, "includeGit", true);

  const hydrated = hydrateSourceScanOptions(edited, savedDefaults);

  assert.deepEqual(hydrated.values, {
    scanSecrets: false,
    scanVulnerabilities: true,
    includeGit: true,
    followSymlinks: true,
    maxFileSizeKb: 777,
  });
  assert.equal(hydrated.resolved, true);
});

test("a failed settings attempt releases truthful fallback controls instead of blocking scans", () => {
  const initial = editSourceScanOption(
    createSourceScanOptions(null),
    "maxFileSizeKb",
    333,
  );

  const fallback = resolveSourceScanOptionsUnavailable(initial);

  assert.equal(fallback.resolved, true);
  assert.deepEqual(buildSourceScanRequest("/project", fallback), {
    path: "/project",
    scanSecrets: true,
    scanVulnerabilities: true,
    includeGit: false,
    followSymlinks: false,
    maxFileSizeKb: 333,
    extraIgnoredDirs: [],
  });
});

test("the submitted Source request is exactly the effective displayed controls", () => {
  let state = createSourceScanOptions(savedDefaults);
  state = editSourceScanOption(state, "scanSecrets", true);
  state = editSourceScanOption(state, "scanVulnerabilities", false);
  state = editSourceScanOption(state, "includeGit", true);
  state = editSourceScanOption(state, "followSymlinks", false);
  state = editSourceScanOption(state, "maxFileSizeKb", 333);

  assert.deepEqual(buildSourceScanRequest("/shown/project", state), {
    path: "/shown/project",
    scanSecrets: true,
    scanVulnerabilities: false,
    includeGit: true,
    followSymlinks: false,
    maxFileSizeKb: 333,
    extraIgnoredDirs: [],
  });
});
