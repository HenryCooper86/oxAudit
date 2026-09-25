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

export interface AdvisoryDbStatus {
  path: string;
  schemaVersion: number;
  ecosystems: string[];
  advisories: number;
  packages: number;
  builtAtMs: number | null;
  updatedAtMs: number | null;
  sizeBytes: number;
}

export interface AdvisoryDbUpdateReport {
  ecosystems: { ecosystem: string; records: number }[];
  totalAdvisories: number;
  totalPackages: number;
  builtAtMs: number;
}

export interface ImageScanRequest {
  target: string;
  advisoryDbPath?: string | null;
  offline: boolean;
}

export interface ImageScanOutcome {
  result: BinaryScanResult;
  notes: string[];
}

export interface VexClaimSet {
  runId: string;
  contentSha256: string;
  format: string;
  claims: number;
  trusted: boolean;
  grantedBy: string | null;
  grantedAtMs: number | null;
}

export interface VexSuggestion {
  advisoryId: string;
  ecosystem: string;
  packageName: string;
  installedVersion: string;
  status: string;
  justification: string;
  documentSha256: string;
  grantedBy: string;
}

export interface VexSuggestions {
  suggestions: VexSuggestion[];
  unmapped: [string, string, string][];
  untrusted: [string, number][];
  runTarget: string;
}

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

/** A pack installed into the managed store; enabled packs apply to every source scan. */
export interface ScanScheduleRecord {
  projectId: string;
  canonicalPath: string;
  displayName: string;
  intervalHours: number;
  enabled: boolean;
  /** RFC 3339 timestamp of the last scan this schedule actually started. */
  lastStartedAt: string | null;
}

export interface ScanScheduleStatus extends ScanScheduleRecord {
  /** Knowable only when enabled and started at least once. */
  nextDueAt: string | null;
}

export interface InstalledRulePack {
  id: string;
  name: string;
  version: string;
  tomlSha256: string;
  contentSha256: string;
  ruleCount: number;
  engines: string[];
  enabled: boolean;
  installedAt: string;
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
  | "cyclonedx-vex"
  | "github-issues-csv"
  | "jira-csv";

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
  | "baselineIncompatible"
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
  gitContext?: GitEvidence | null;
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

export interface RecheckSourceResult {
  run: ScanRunDetail;
  options: ScanOptions;
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
  countsAvailable?: boolean | null;
  openFindings: number;
  critical: number;
  high: number;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
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
  /** The run's findings by severity; zeroed for runs that never completed. */
  severityCounts: SeverityCounts;
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

export interface DependencyStep {
  name: string;
  packageName: string;
  installPath: string;
  dependencyType: string;
  declared: string;
}
export interface DependencyPath {
  workspace: string;
  entryPoint: string;
  chain: DependencyStep[];
}
export interface DependencyOccurrence {
  localWorkspace?: boolean;
  installPath: string | null;
  status: string;
  paths: DependencyPath[];
  warnings: string[];
}
export interface AffectedEvidence {
  ecosystem: string;
  packageName: string;
  records: Array<{
    package?: { ecosystem?: string; name?: string };
    ranges?: Array<{ type?: string; events?: Array<Record<string, unknown>> }>;
    versions?: string[];
  }>;
}

export interface Dependency {
  occurrence?: DependencyOccurrence;
  ecosystem: string;
  name: string;
  version: string;
  lockfile: string;
  /** Declared license when the lockfile carries it (npm package-lock v2/v3). */
  license?: string | null;
}

export interface Vulnerability {
  occurrence?: DependencyOccurrence;
  affectedEvidence?: AffectedEvidence | null;
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
  /** Public exploit code exists for this CVE (Exploit-DB). */
  publicExploit: boolean;
  /** Whether the project's own source references this package. */
  directUsage: {
    /** true = confirmed; false = completely indexed and not found; null = unmapped or incomplete. */
    referenced: boolean | null;
    referencedFiles: number;
    exampleFile: string | null;
  };
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
  runId?: string | null;
  advisoryFetchedAtMs?: number | null;
  advisorySource?: string;
  /** Absent in older runs; false exploitation flags then mean unknown. */
  enrichment?: {
    status: "unknown" | "notApplicable" | "unavailable" | "available" | "partial";
    checkedAtMs: number | null;
    pocCacheUpdatedAtMs: number | null;
    warnings: string[];
  };
  path: string;
  lockfilesFound: string[];
  packagesFound: number;
  packagesQueried: number;
  /** Older saved runs did not record whether every package had advisory coverage. */
  advisoryCoverage?: "complete" | "unknown";
  /** Present when a local advisory database answered: honest limits hit while matching (undetermined comparisons, skipped GIT ranges). */
  advisoryNotes?: string[];
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
  editor: "system" | "vscode";
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
  /** Public exploit code exists for this CVE (Exploit-DB). */
  publicExploit: boolean;
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


export interface GitSnapshot {
  branch: string | null;
  head: string;
  indexDigest: string;
}
export interface GitEvidence {
  before: GitSnapshot | null;
  after: GitSnapshot | null;
  contextChanged: boolean | null;
}
export interface GitContext {
  target: string;
  snapshot: GitSnapshot;
  baseReference: string;
  baseCommit: string;
  changedPaths: string[];
  stagedPaths: string[];
  unstagedPaths: string[];
  partiallyStaged: boolean;
  inspectedAt: string;
}

export interface HistoryValidationSummary {
  checked: number;
  live: number;
  rejected: number;
  skippedNoValidator: number;
  skippedUnpaired: number;
  skippedLimit: number;
  skippedNotKept: number;
}

/**
 * The whole result of a git-history secret scan. Not a stored run: findings
 * describe objects in git history, not the working tree a canonical run's
 * projection is indexed against, so the response is the entire run and is
 * gone when the page is.
 */
export interface HistoryScanResult {
  findings: Finding[];
  blobsScanned: number;
  blobsSkipped: number;
  truncated: boolean;
  limitNote: string | null;
  /** Present only when live validation was opted into for this run. */
  validation: HistoryValidationSummary | null;
}
