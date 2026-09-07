import type {
  AppSettings,
  DependencyScanResult,
  ProjectContext,
  ScanRunDetail,
} from "../../src/lib/types";
export const projectSettings: AppSettings = {
  editor: "system",
  ai: {
    enabled: false,
    baseUrl: "",
    model: "",
    temperature: 0.2,
    timeoutSecs: 60,
    maxTokens: 2048,
    contextWindow: 128000,
    systemPrompt: "",
  },
  scan: {
    scanSecrets: true,
    scanVulnerabilities: true,
    maxFileSizeKb: 777,
    includeGit: false,
    followSymlinks: false,
    ignoredDirs: [],
  },
  credentials: { aiApiKey: false, nvdApiKey: false },
  theme: "dark",
  binaryScannerPath: null,
  binaryScannerRuntime: null,
  grypePath: null,
  agentAllowedFetchHosts: [],
};
export function projectContext(path: string): ProjectContext {
  return {
    projectId: path,
    canonicalPath: path,
    displayName: path.split("/").pop() ?? path,
    lastCompletedRunId: null,
    lastOptions: null,
    policy: { status: "missing" },
  };
}
export function sourceResult(path = "/real/project"): ScanRunDetail {
  return {
    projectId: path,
    runId: "s",
    baselineRunId: null,
    status: "completed",
    persistence: { status: "saved" },
    policy: { status: "missing" },
    startedAt: "2026-09-07T00:00:00Z",
    completedAt: "2026-09-07T00:01:00Z",
    maintenanceWarning: null,
    findings: [],
    summary: {
      path,
      filesScanned: 1,
      filesSkipped: 0,
      bytesScanned: 10,
      durationMs: 1,
      secretsFound: 0,
      vulnerabilitiesFound: 0,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      rulesFired: {},
    },
  };
}
export function dependencyResult(path = "/real/project"): DependencyScanResult {
  return {
    summary: {
      path,
      lockfilesFound: ["package-lock.json"],
      packagesFound: 1,
      packagesQueried: 1,
      vulnerabilitiesFound: 0,
      durationMs: 1,
      advisoryCoverage: "complete",
    },
    dependencies: [],
    vulnerabilities: [],
  };
}
