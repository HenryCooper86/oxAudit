// Types mirroring the Rust backend models (camelCase via serde rename_all).

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingScope =
  | "production"
  | "infrastructure"
  | "test"
  | "fixture"
  | "generated"
  | "vendored"
  | "documentation"
  | "unknown";

export type ReviewState =
  | "candidate"
  | "confirmed"
  | "falsePositive"
  | "acceptedRisk"
  | "suppressed";

export type DiffStatus = "new" | "unchanged" | "resolved" | "notEvaluated";
export type RunStatus = "running" | "completed" | "incomplete";
export type CanonicalRunKind =
  | "source"
  | "secrets"
  | "dependencies"
  | "binary"
  | "firmware"
  | "import"
  | "external_evidence"
  | "verification";
export type CanonicalRunState =
  | "queued"
  | "discovering"
  | "detecting"
  | "normalizing"
  | "enriching"
  | "assessing"
  | "persisting"
  | "completed"
  | "cancelling"
  | "cancelled"
  | "incomplete"
  | "failed"
  | "verifying";

export interface CanonicalRun {
  id: string;
  kind: CanonicalRunKind;
  targetLabel: string;
  state: CanonicalRunState;
  attempt: number;
  createdAtMs: number;
  updatedAtMs: number;
  engineIds: string[];
  rulePackIds: string[];
  providerSnapshotIds: string[];
  warnings: Array<{ code: string; message: string }>;
}

export interface RuleLibraryRuleStatus {
  id: string;
  title: string;
  severity: string;
  scope: string[];
  fixtureHealth: "verified" | "unitTested" | "coverageNeeded";
  provenance: string;
}

export interface RuleLibraryPackStatus {
  id: string;
  name: string;
  version: string;
  engine: string;
  enabled: boolean;
  license: string;
  source: string;
  creationMethod: string;
  contentSha256: string;
  validation: string;
  fixtureSummary: string;
  rules: RuleLibraryRuleStatus[];
}

export interface RulePackValidationPreview {
  id: string;
  name: string;
  version: string;
  contentSha256: string;
  ruleCount: number;
  engines: string[];
  fixtureCount: number;
  license: string;
  source: string;
  validation: string;
}

export interface QualityStatus {
  schemaVersion: number;
  suiteId: string;
  suiteVersion: string;
  description: string;
  corpusTargets: number;
  passedTargets: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number | null;
  recall: number | null;
  runtimeMs: number;
  misses: string[];
  unexpected: string[];
  limitation: string;
  previousPrecision: number | null;
  previousRecall: number | null;
  regression: boolean;
}

export interface DataSourceStatus {
  id: string;
  name: string;
  sourceUrl: string;
  termsUrl: string;
  license: string;
  state: "notRefreshed" | "onlineCached" | "offlineReady" | "failed";
  supportsOffline: boolean;
  activeSnapshotId: string | null;
  fetchedAtMs: number | null;
  contentSha256: string | null;
  recordCount: number | null;
  validation: string;
  limitation: string;
}

export type ExportFormat =
  | "oxaudit-json"
  | "sarif"
  | "cyclonedx"
  | "spdx"
  | "openvex"
  | "cyclonedx-vex";

export interface ExportPreview {
  format: ExportFormat;
  mediaType: string;
  suggestedFileName: string;
  valid: boolean;
  warnings: string[];
  artifacts: number;
  components: number;
  observations: number;
  content: string;
  truncated: boolean;
}

export interface ImportPreview {
  format: ExportFormat;
  mediaType: string;
  fileName: string;
  contentSha256: string;
  componentRecords: number;
  findingRecords: number;
  reviewRecords: number;
  conflictCount: number;
  conflicts: string[];
  unmappedCount: number;
  unmappedRecords: string[];
  warnings: string[];
  canImportInventory: boolean;
  mappedClaimCount: number;
  mappedClaims: ExternalClaim[];
  canImportExternalClaims: boolean;
}

export interface ExternalClaimLocation {
  uri: string;
  startLine: number | null;
  startColumn: number | null;
}

export interface ExternalClaim {
  recordId: string;
  claimKind: string;
  producer: string;
  ruleId: string | null;
  vulnerabilityId: string | null;
  subjectIds: string[];
  status: string;
  summary: string;
  location: ExternalClaimLocation | null;
  trust: "external-unverified";
}

export interface InventoryIdentityView {
  method: string;
  value: string;
  confidence: number;
  artifactId: string;
  artifactPath: string;
}

export interface InventoryComponentView {
  id: string;
  name: string;
  version: string | null;
  supplier: string | null;
  ecosystem: string | null;
  purl: string | null;
  cpes: string[];
  aliases: string[];
  identities: InventoryIdentityView[];
  advisoryIds: string[];
}

export interface InventoryView {
  runId: string;
  targetLabel: string;
  runKind: CanonicalRunKind;
  updatedAtMs: number;
  providerSnapshotCount: number;
  components: InventoryComponentView[];
}

export interface CanonicalFinding {
  id: string;
  runId: string;
  fingerprint: string;
  fingerprintVersion: number;
  title: string;
  severity: Severity;
  state: "candidate" | "confirmed" | "false_positive" | "accepted_risk" | "suppressed";
  classifications: string[];
  observationIds: string[];
  evidenceIds: string[];
}

export type VerificationResult = "supported" | "refuted" | "inconclusive";

export interface VerificationRecord {
  id: string;
  findingId: string;
  producerId: string;
  verifier: { kind: string; id: string; version: string };
  inputSnapshotSha256: string;
  result: VerificationResult;
  evidenceDelta: string[];
  limitations: string[];
  verifiedAtMs: number;
}

export type ComplianceAssurance = "automatedEvidence" | "humanAttestation" | "mixed";
export type ComplianceReadinessStatus =
  | "supported"
  | "partial"
  | "gap"
  | "manualReview"
  | "notApplicable";

export interface ComplianceCheckSpec {
  fileGroups: string[][];
  runKinds: CanonicalRunKind[];
  manual: boolean;
}

export interface ComplianceControlProfile {
  id: string;
  reference: string;
  title: string;
  objective: string;
  assurance: ComplianceAssurance;
  check: ComplianceCheckSpec;
}

export interface ComplianceProfile {
  schemaVersion: number;
  id: string;
  name: string;
  version: string;
  domain: string;
  jurisdiction: string;
  sourceLabel: string;
  sourceUrl: string;
  copyrightNotice: string;
  disclaimer: string;
  controls: ComplianceControlProfile[];
}

export interface ComplianceEvidenceReference {
  kind: string;
  label: string;
  locator: string;
  contentSha256: string | null;
}

export interface ComplianceControlAssessment {
  controlId: string;
  reference: string;
  title: string;
  objective: string;
  assurance: ComplianceAssurance;
  automatedStatus: ComplianceReadinessStatus;
  rationale: string;
  evidence: ComplianceEvidenceReference[];
}

export interface ComplianceAssessmentSummary {
  total: number;
  supported: number;
  partial: number;
  gap: number;
  manualReview: number;
  notApplicable: number;
  evidenceCoveragePercent: number;
}

export interface ComplianceAssessment {
  schemaVersion: number;
  id: string;
  profileId: string;
  profileName: string;
  profileVersion: string;
  domain: string;
  sourceLabel: string;
  sourceUrl: string;
  disclaimer: string;
  metadata: {
    title: string;
    organization: string;
    assessor: string;
    scope: string;
  };
  targetLabel: string;
  createdAtMs: number;
  controls: ComplianceControlAssessment[];
  summary: ComplianceAssessmentSummary;
  collectionLimits: string[];
}

export interface ComplianceReview {
  id: string;
  assessmentId: string;
  controlId: string;
  status: ComplianceReadinessStatus;
  note: string;
  author: string;
  reviewedAtMs: number;
}

export interface ComplianceAssessmentView {
  assessment: ComplianceAssessment;
  reviews: ComplianceReview[];
}

export interface RunComplianceRequest {
  targetPath: string;
  profileIds: string[];
  title: string;
  organization: string;
  assessor: string;
  scope: string;
}

export type ComplianceReportFormat = "json" | "csv" | "markdown" | "html" | "pdf";

export interface ComplianceReportMetadata {
  title: string;
  organization: string;
  assessor: string;
  classification: string;
  executiveSummary: string;
  includeEvidence: boolean;
  includeReviews: boolean;
  includeReferences: boolean;
}

export interface ComplianceReportRequest {
  assessmentId: string;
  format: ComplianceReportFormat;
  metadata: ComplianceReportMetadata;
}

export interface ComplianceReportPreview {
  format: ComplianceReportFormat;
  mediaType: string;
  suggestedFileName: string;
  content: string;
  truncated: boolean;
  bytes: number;
  warnings: string[];
}

export interface ComplianceReportReceipt {
  id: string;
  assessmentId: string;
  format: ComplianceReportFormat;
  outputPath: string;
  contentSha256: string;
  createdAtMs: number;
  metadata: ComplianceReportMetadata;
}
export type ReviewOrigin = "local" | "projectPolicy";
export type Gate =
  | "intended"
  | "reachable"
  | "attackerControlled"
  | "sanitized"
  | "newCapability";
export type GateVerdict = "survives" | "eliminates" | "unknown";

export interface GateNote {
  gate: Gate;
  verdict: GateVerdict;
  evidence: string;
}

export type PolicyStatus =
  | { status: "missing" }
  | { status: "valid"; hash: string }
  | { status: "invalid"; message: string };

export type RunPersistence =
  | { status: "saved" }
  | { status: "notSaved"; retryToken: string };

export type ErrorCode =
  | "invalidTarget"
  | "scanCancelled"
  | "scanFailed"
  | "scanAlreadyRunning"
  | "persistenceUnavailable"
  | "policyInvalid"
  | "policyWriteFailed"
  | "reviewInvalid"
  | "notFound"
  | "credentialUnavailable"
  | "credentialRollbackFailed"
  | "migrationFailed"
  | "dataOperationFailed";

export interface CommandError {
  code: ErrorCode;
  message: string;
  detail: string | null;
  retryable: boolean;
}

export interface ScanOptions {
  path: string;
  includeGit: boolean;
  followSymlinks: boolean;
  maxFileSizeKb: number;
  scanSecrets: boolean;
  scanVulnerabilities: boolean;
  extraIgnoredDirs: string[];
  ignoreInvalidPolicy: boolean;
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

export type AnalysisTier = "text" | "syntax";

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
  /** This finding's CWE is represented in CISA KEV — the weakness class is
   *  being actively exploited in the wild. A class-level signal, not a CVE. */
  cweExploited: boolean;
  /** How many exploited CVEs share this finding's CWE. */
  cweExploitedCount: number;
  recommendation: string;
  entropy: number | null;
  verified: boolean | null;
  /**
   * How far oxAudit could qualify this match. `syntax` means a grammar parsed
   * the file and the match sits in code; `text` means the rule matched raw file
   * text with no grammar available for the language.
   */
  analysis: AnalysisTier;
  /**
   * What the dataflow analysis worked out, phrased as answers to the
   * falsification gates. Suggestions, never decisions — the review form starts
   * from these and a person submits it.
   */
  analysisGates: GateNote[];
  observationRunId: string;
  resolvedByRunId: string | null;
  fingerprintVersion: number;
  fingerprint: string;
  scope: FindingScope | null;
  scopeReason: string | null;
  review: ReviewRecord | null;
  reviewHistory: ReviewRecord[];
  diffStatus: DiffStatus | null;
}

export interface ScanResult {
  summary: ScanSummary;
  findings: Finding[];
}

export interface ReviewRecord {
  id: string;
  projectId: string;
  fingerprintVersion: number;
  fingerprint: string;
  state: ReviewState;
  reason: string;
  evidence: string | null;
  entryPoint: string | null;
  dataFlow: string | null;
  gates: GateNote[];
  decidingGate: Gate | null;
  expiresAt: string | null;
  origin: ReviewOrigin;
  policyHash: string | null;
  updatedAt: string;
  supersededAt: string | null;
}

export interface ScanRunDetail {
  projectId: string;
  runId: string;
  baselineRunId: string | null;
  status: RunStatus;
  persistence: RunPersistence;
  policy: PolicyStatus;
  startedAt: string;
  completedAt: string | null;
  summary: ScanSummary;
  findings: Finding[];
  maintenanceWarning: string | null;
}

export interface ProjectContext {
  projectId: string;
  canonicalPath: string;
  displayName: string;
  policy: PolicyStatus;
  lastCompletedRunId: string | null;
  lastOptions: ScanOptions | null;
}

export interface RecentProject {
  projectId: string;
  canonicalPath: string;
  displayName: string;
  lastOpenedAt: string;
  lastCompletedRunId: string | null;
  lastCompletedAt: string | null;
  openFindings: number;
  critical: number;
  high: number;
}

export interface ScanRunSummary {
  runId: string;
  projectId: string;
  status: RunStatus;
  startedAt: string;
  completedAt: string | null;
  totalFindings: number;
  newFindings: number;
  resolvedFindings: number;
}

export interface ReviewRequest {
  projectId: string;
  fingerprintVersion: number;
  fingerprint: string;
  category: Finding["category"];
  state: ReviewState;
  reason: string;
  evidence: string | null;
  entryPoint: string | null;
  dataFlow: string | null;
  gates: GateNote[];
  decidingGate: Gate | null;
  expiresAt: string | null;
  origin: ReviewOrigin;
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
  /** EPSS probability of exploitation in the next 30 days, 0-1. */
  epss: number | null;
  /** EPSS percentile against all scored CVEs, 0-1. */
  epssPercentile: number | null;
  /** In CISA's Known Exploited Vulnerabilities catalog. */
  knownExploited: boolean;
  /** Named in a ransomware campaign, per KEV. */
  ransomware: boolean;
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
  /** EPSS probability of exploitation in the next 30 days, 0-1. */
  epss: number | null;
  /** EPSS percentile against all scored CVEs, 0-1. */
  epssPercentile: number | null;
  /** In CISA's Known Exploited Vulnerabilities catalog. */
  knownExploited: boolean;
  /** Named in a ransomware campaign, per KEV. */
  ransomware: boolean;
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
  model: string;
  temperature: number;
  timeoutSecs: number;
  maxTokens: number;
  /** Model input + output capacity used for local preflight and UI metadata. */
  contextWindow: number;
  systemPrompt: string;
}

export interface CredentialPresence {
  aiApiKey: boolean;
  nvdApiKey: boolean;
}

export type CredentialMutation =
  | { action: "unchanged" }
  | { action: "replace"; value: string }
  | { action: "delete" };

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
  credentials: CredentialPresence;
  theme: string;
  /** Explicit cve-bin-tool path; null/empty means "find it on PATH". */
  binaryScannerPath: string | null;
  /** How cve-bin-tool runs. Docker is often the runtime that works. */
  binaryScannerRuntime: BinaryScannerRuntime | null;
  /** Explicit grype path; null/empty means "find it on PATH". */
  grypePath: string | null;
  /**
   * Extra hosts the assistant's `web_fetch` tool may read from, on top of the
   * built-in advisory sources. Entries may be bare hosts or pasted URLs.
   */
  agentAllowedFetchHosts: string[];
}

export interface SaveSettingsRequest {
  settings: AppSettings;
  aiApiKey: CredentialMutation;
  nvdApiKey: CredentialMutation;
}

export interface SaveSettingsResult {
  settings: AppSettings;
}

export interface TestAiRequest {
  settings: AiSettings;
  aiApiKey: CredentialMutation;
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
  semanticAnalysis?: SemanticAnalysisReport;
}

export interface SemanticAnalysisReport {
  architecture: string;
  functionsAnalyzed: number;
  callEdges: number;
  unresolvedEdges: number;
  findings: Array<{
    ruleId: string;
    functionAddress: number;
    confidence: number;
    evidence: unknown[];
    limitations: string[];
  }>;
  limitations: string[];
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
  deepAnalysis?: boolean;
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
  /** When false, skip auto-compaction and send the full history as-is. */
  allowCompaction?: boolean;
}

export interface StreamStarted {
  runId: string;
}

/** Tagged union of live AI stream events (mirrors Rust `AiStreamEvent`). */
export type AiStreamEvent = { runId: string } & (
  | { type: "delta"; content: string }
  | { type: "reasoning"; content: string }
  | { type: "usage"; usage: Usage }
  | {
      type: "context_budget";
      estimatedTokens: number;
      contextWindow: number;
      reservedOutputTokens: number;
    }
  | {
      type: "context_compacted";
      summarizedMessages: number;
      summary: string;
    }
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
  /** Present when this answer was generated from a compacted conversation. */
  compaction?: { summarizedMessages: number; summary: string };
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

/** What a person needs in order to report a problem. Redacted before it arrives. */
export interface Diagnostics {
  version: string;
  os: string;
  architecture: string;
  /** Whether an AI endpoint is configured — never which one, and never the key. */
  aiConfigured: boolean;
  logPath: string | null;
  logBytes: number;
  /** Tail of the log, with credentials and home directory paths removed. */
  logTail: string;
  notes: string[];
}

/** One finding a bulk review could not be recorded against. */
export interface BulkReviewFailure {
  fingerprint: string;
  message: string;
}

/**
 * What a bulk review actually did.
 *
 * Both halves are reported: a caller that only learns "it worked" cannot tell a
 * reviewer that three of their forty decisions did not land.
 */
export interface BulkReviewOutcome {
  recorded: ReviewRecord[];
  failures: BulkReviewFailure[];
}
