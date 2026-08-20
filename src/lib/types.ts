// Types mirroring the Rust backend models (camelCase via serde rename_all).

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ScanOptions {
  path: string;
  includeGit: boolean;
  followSymlinks: boolean;
  maxFileSizeKb: number;
  scanSecrets: boolean;
  scanVulnerabilities: boolean;
  extraIgnoredDirs: string[];
}

export interface ScanSummary {
  path: string;
  filesScanned: number;
  filesSkipped: number;
  bytesScanned: number;
  durationMs: number;
  secretsFound: number;
  vulnerabilitiesFound: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  rulesFired: Record<string, number>;
}

export interface Finding {
  id: string;
  category: "secret" | "vulnerability";
  ruleId: string;
  ruleName: string;
  severity: Severity;
  title: string;
  description: string;
  filePath: string;
  line: number;
  column: number;
  matchText: string;
  context: string;
  language: string;
  cwe: string | null;
  recommendation: string;
  entropy: number | null;
  verified: boolean | null;
}

export interface ScanResult {
  summary: ScanSummary;
  findings: Finding[];
}

export interface ScanProgress {
  total?: number;
  done?: number;
  phase?: "walking" | "scanning" | string;
  file?: string;
  parseErrors?: number;
}

export interface Dependency {
  ecosystem: string;
  name: string;
  version: string;
  lockfile: string;
}

export interface Vulnerability {
  id: string;
  aliases: string[];
  summary: string;
  details: string;
  severity: string | null;
  cvssScore: number | null;
  ecosystem: string;
  packageName: string;
  installedVersion: string;
  fixedVersions: string[];
  affectedRange: string | null;
  references: string[];
  published: string | null;
  modified: string | null;
  lockfile: string;
}

export interface DepScanSummary {
  path: string;
  lockfilesFound: string[];
  packagesFound: number;
  packagesQueried: number;
  vulnerabilitiesFound: number;
  durationMs: number;
}

export interface DependencyScanResult {
  summary: DepScanSummary;
  dependencies: Dependency[];
  vulnerabilities: Vulnerability[];
}

export interface LockfileInfo {
  path: string;
  kind: string;
  packages: number;
}

export interface CveItem {
  id: string;
  severity: string | null;
  cvssScore: number | null;
  description: string;
  published: string | null;
  modified: string | null;
  affectedProducts: string[];
  references: string[];
  cwes: string[];
}

export interface CveSearchResult {
  total: number;
  items: CveItem[];
}

export interface CveDetail {
  item: CveItem;
  raw: unknown;
  osv: unknown | null;
}

export interface AiSettings {
  enabled: boolean;
  baseUrl: string;
  apiKey: string;
  model: string;
  temperature: number;
  timeoutSecs: number;
  maxTokens: number;
  systemPrompt: string;
}

export interface ScanSettings {
  maxFileSizeKb: number;
  followSymlinks: boolean;
  includeGit: boolean;
  ignoredDirs: string[];
  scanSecrets: boolean;
  scanVulnerabilities: boolean;
}

export interface AppSettings {
  ai: AiSettings;
  scan: ScanSettings;
  nvdApiKey: string | null;
  theme: string;
  /** Explicit cve-bin-tool path; null/empty means "find it on PATH". */
  binaryScannerPath: string | null;
  /** How cve-bin-tool runs. Docker is often the runtime that works. */
  binaryScannerRuntime: BinaryScannerRuntime | null;
  /** Explicit grype path; null/empty means "find it on PATH". */
  grypePath: string | null;
}

export type BinaryScannerRuntime = "auto" | "native" | "docker";

/** Where a detected cve-bin-tool came from. */
export type BinaryToolSource = "configured" | "path" | "pythonModule";

export interface BinaryToolStatus {
  available: boolean;
  program: string | null;
  version: string | null;
  source: BinaryToolSource | null;
  message: string | null;
}

export interface BinaryVulnerability {
  cveId: string;
  severity: string;
  score: number | null;
  cvssVersion: string | null;
  cvssVector: string | null;
  source: string;
  remarks: string | null;
  epssProbability: number | null;
  /** EPSS percentile against all scored CVEs, 0-1. */
  epssPercentile: number | null;
  /** In CISA's Known Exploited Vulnerabilities catalog. */
  knownExploited: boolean;
  /** Named in a ransomware campaign, per KEV. */
  ransomware: boolean;
  /** First version carrying the fix. grype reports this; cve-bin-tool does not. */
  fixedIn: string | null;
}

export interface BinaryComponent {
  vendor: string;
  product: string;
  version: string;
  paths: string[];
  vulnerabilities: BinaryVulnerability[];
  /** Which scanners saw this component. */
  detectedBy: string[];
}

export interface BinaryScanSummary {
  components: number;
  vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  /// Findings the source rated at nothing; the buckets always sum to
  /// `vulnerabilities`.
  unknown: number;
}

export interface BinaryScanResult {
  target: string;
  components: BinaryComponent[];
  summary: BinaryScanSummary;
  databaseLastUpdated: string | null;
  durationMs: number;
  /** Scanners that contributed to this result. */
  scanners: string[];
}

export interface BinaryScannersStatus {
  /** oxAudit's built-in scanner — always available, needs nothing installed. */
  native: BinaryToolStatus;
  cveBinTool: BinaryToolStatus;
  grype: BinaryToolStatus;
  docker: BinaryToolStatus;
  runtime: BinaryScannerRuntime;
  /** Whether any scanner can run. Always true — the native scanner is built in. */
  canScan: boolean;
}

export interface BinaryScanRequest {
  path: string;
  severity?: string | null;
  offline?: boolean;
  update?: string | null;
}

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface ChatRequest {
  messages: ChatMessage[];
  temperature?: number;
  maxTokens?: number;
  conversationId?: string;
}

export interface StreamStarted {
  runId: string;
}

/** Tagged union of live AI stream events (mirrors Rust `AiStreamEvent`). */
export type AiStreamEvent = { runId: string } & (
  | { type: "delta"; content: string }
  | { type: "reasoning"; content: string }
  | { type: "usage"; usage: Usage }
  | { type: "tool_start"; toolCallId: string; name: string; arguments: string }
  | {
      type: "tool_result";
      toolCallId: string;
      name: string;
      success: boolean;
      durationMs: number;
      resultPreview: string;
    }
  | { type: "ask_user"; requestId: string; questions: AskQuestion[] }
  | { type: "steer"; text: string }
  | { type: "todos"; items: TodoItem[] }
  | { type: "permission_request"; requestId: string; tool: string; arguments: string }
);

/** One entry in the agent's per-conversation todo list. */
export interface TodoItem {
  id: number;
  text: string;
  status: "pending" | "done";
}

export interface AskQuestion {
  prompt: string;
  options?: string[];
  multi_select?: boolean;
}

/** Display record for a tool call (rendered by ToolCallCard). */
export interface ToolRecord {
  toolCallId: string;
  name: string;
  arguments: string;
  status: "running" | "success" | "error";
  durationMs: number | null;
  resultPreview: string | null;
}

export interface AiDonePayload {
  runId: string;
  content: string;
  model: string | null;
  usage: Usage | null;
}

export interface UsageSummary {
  turns: number;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  costUsd: number;
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export interface SessionInfo {
  id: string;
  title: string;
  autoTitle: boolean;
  createdAt: string;
  updatedAt: string;
  messageCount: number;
  projectPath: string | null;
}

export interface StoredMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  tools?: ToolRecord[];
  model?: string | null;
  at: string;
}

export interface Usage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

export interface ChatResponse {
  content: string;
  model: string | null;
  usage: Usage | null;
}

export interface AiStatus {
  ok: boolean;
  message: string;
  model: string | null;
  latencyMs: number;
}
