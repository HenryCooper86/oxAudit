import type { ScanOptions, ScanSettings } from "./types";

export interface SourceScanOptionValues {
  scanSecrets: boolean;
  scanVulnerabilities: boolean;
  includeGit: boolean;
  followSymlinks: boolean;
  maxFileSizeKb: number;
}

export type SourceScanOptionKey = keyof SourceScanOptionValues;

export interface SourceScanOptionsState {
  values: SourceScanOptionValues;
  edited: Record<SourceScanOptionKey, boolean>;
  resolved: boolean;
}

const FALLBACK_VALUES: SourceScanOptionValues = {
  scanSecrets: true,
  scanVulnerabilities: true,
  includeGit: false,
  followSymlinks: false,
  maxFileSizeKb: 1024,
};

const UNEDITED: Record<SourceScanOptionKey, boolean> = {
  scanSecrets: false,
  scanVulnerabilities: false,
  includeGit: false,
  followSymlinks: false,
  maxFileSizeKb: false,
};

function valuesFromSettings(settings: ScanSettings): SourceScanOptionValues {
  return {
    scanSecrets: settings.scanSecrets,
    scanVulnerabilities: settings.scanVulnerabilities,
    includeGit: settings.includeGit,
    followSymlinks: settings.followSymlinks,
    maxFileSizeKb: settings.maxFileSizeKb,
  };
}

export function createSourceScanOptions(
  settings: ScanSettings | null,
): SourceScanOptionsState {
  return {
    values: settings ? valuesFromSettings(settings) : { ...FALLBACK_VALUES },
    edited: { ...UNEDITED },
    resolved: settings !== null,
  };
}

export function editSourceScanOption<K extends SourceScanOptionKey>(
  state: SourceScanOptionsState,
  key: K,
  value: SourceScanOptionValues[K],
): SourceScanOptionsState {
  return {
    ...state,
    values: { ...state.values, [key]: value },
    edited: { ...state.edited, [key]: true },
  };
}

export function hydrateSourceScanOptions(
  state: SourceScanOptionsState,
  settings: ScanSettings,
): SourceScanOptionsState {
  if (state.resolved) return state;
  const loaded = valuesFromSettings(settings);
  const values = { ...state.values };
  for (const key of Object.keys(loaded) as SourceScanOptionKey[]) {
    if (!state.edited[key]) values[key] = loaded[key] as never;
  }
  return { ...state, values, resolved: true };
}

export function resolveSourceScanOptionsUnavailable(
  state: SourceScanOptionsState,
): SourceScanOptionsState {
  return state.resolved ? state : { ...state, resolved: true };
}

export function hydrateSourceScanOptionsFromProject(
  state: SourceScanOptionsState,
  options: ScanOptions | null,
): SourceScanOptionsState {
  if (!options) return state;
  const loaded: SourceScanOptionValues = {
    scanSecrets: options.scanSecrets,
    scanVulnerabilities: options.scanVulnerabilities,
    includeGit: options.includeGit,
    followSymlinks: options.followSymlinks,
    maxFileSizeKb: options.maxFileSizeKb,
  };
  const values = { ...state.values };
  for (const key of Object.keys(loaded) as SourceScanOptionKey[]) {
    if (!state.edited[key]) values[key] = loaded[key] as never;
  }
  return { ...state, values, resolved: true };
}

export function buildSourceScanRequest(
  path: string,
  state: SourceScanOptionsState,
  ignoreInvalidPolicy = false,
): ScanOptions {
  return {
    path,
    ...state.values,
    extraIgnoredDirs: [],
    ignoreInvalidPolicy,
  };
}
