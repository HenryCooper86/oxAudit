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
  | { type: "permission_request"; requestId: string; tool: string; arguments: string }
);

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
