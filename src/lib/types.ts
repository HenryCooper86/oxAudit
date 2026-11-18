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
  | "image"
  | "history"
  | "firmware"
  | "import"
  | "external_evidence"
  | "verification"
  | "yara"
  | "template";
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
  operationId?: string;
  target: string;
  advisoryDbPath?: string | null;
  offline: boolean;
}

export interface ImageScanOutcome {
  runId: string;
  result: BinaryScanResult;
  notes: string[];
  imageDigest: string | null;
  layers: Array<{ name: string; digest: string; sizeBytes: number; mediaType: string | null }>;
  offline: boolean;
  advisoryDbPath?: string | null;
  localEvidence?: {
    kind: "file" | "oci-layout" | "directory" | "unavailable";
    complete: boolean;
    hashByteLimit: number;
    file?: {
      sizeBytes: number; sizeSource: string; bytesHashed: number;
      sha256: string | null; prefixSha256: string | null;
      changedDuringRead: boolean | null; complete: boolean;
    };
    oci?: { indexSha256: string | null; indexes?: unknown[]; manifests?: unknown[] };
    notes: string[];
  };
  /** Canonical terminal state when loading saved evidence. */
  state?: CanonicalRunState;
}

export type ScanWorkKind = "source" | "dependencies" | "binary" | "image" | "history" | "yara" | "template";
export type ScanWorkStatus = "running" | "cancelling" | "completed" | "failed" | "cancelled" | "incomplete";
export interface ScanWorkDescriptor {
  operationId: string;
  kind: ScanWorkKind;
  target: string;
  status: ScanWorkStatus;
  runId?: string | null;
  startedAtMs: number;
  updatedAtMs: number;
}
export interface ScanWorkSnapshot {
  active: ScanWorkDescriptor | null;
  recent: ScanWorkDescriptor[];
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

/** A pack installed into the managed store; its enabled text-engine rules apply to every source scan. */
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

/** Confusion counts for one OWASP Benchmark slice. */
export interface BenchmarkCounts {
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
}

export interface BenchmarkCategoryScore extends BenchmarkCounts {
  category: string;
  cwe: number;
  /** False when oxAudit has no Java rule for this weakness class at all. */
  covered: boolean;
}

/** Result of scoring a local OWASP Benchmark checkout (Quality Lab). */
export interface ExternalBenchmarkReport {
  suite: string;
  cases: number;
  /** Totals over the categories oxAudit has Java rules for. */
  coveredTotals: BenchmarkCounts;
  /** Totals over the categories it does not — absent rules, not wrong ones. */
  uncoveredTotals: BenchmarkCounts;
  categories: BenchmarkCategoryScore[];
  runtimeMs: number;
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

export interface InventoryPage extends ResultPage<InventoryComponentView>, Omit<InventoryView, "components"> {}

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
  | "nothingToScan"
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
  /** Pack files applied to this run only, without installing them. */
  extraRulePackFiles: string[];
}

export interface ScanSummary {
  coverageWarnings?: string[];
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

/** Saved context only; loadSourceRun remains the complete export/recheck contract. */
export type SourceRunMetadata = Omit<ScanRunDetail, "findings">;

export interface ResultPageQuery {
  offset?: number;
  limit?: number;
  search?: string;
  severity?: Severity | "unknown" | "all" | null;
  minimumSeverity?: Severity | "unknown" | "all" | null;
  sort?: "original" | "severity" | "file" | "rule";
}

export interface ResultPage<T> {
  items: T[];
  offset: number;
  limit: number;
  filteredTotal: number;
  total: number;
  related?: { blobs: NonNullable<HistoryScanResult["blobs"]>; findingBlobIds: Record<string, string> };
}

export interface SourceFindingsQuery extends ResultPageQuery {
  view?: "all" | "open" | "otherScopes" | "closed" | "resolved";
  newOnly?: boolean;
  category?: "all" | "secret" | "vulnerability";
  scope?: "all" | FindingScope;
  language?: string;
  baselineRunId?: string | null;
  filePaths?: string[] | null;
  requireValidPolicy?: boolean;
}

export interface SourceFindingsPage extends ResultPage<Finding> {
  viewCounts: Record<"open" | "otherScopes" | "closed" | "resolved", number>;
  diffCounts: Record<DiffStatus, number>;
  languages: string[];
}

export type CanonicalProjectionSection = "dependencies" | "vulnerabilities" | "components" | "semanticFindings" | "layers" | "findings" | "blobs" | "matches" | "skipped" | "notEvaluated";

/** List arrays in projection are empty placeholders; sections supplies authoritative totals. */
export interface CanonicalProjectionMetadata<T> {
  kind: "pagedProjection";
  projectionKind: string;
  projection: T;
  sections: Partial<Record<CanonicalProjectionSection, number>>;
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
  operationId?: string;
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
  source?: string;
  platform?: string;
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
  /** Functions the advisory names as affected (RustSec only); referencedFunctions is the subset this project references. */
  affectedFunctions?: string[];
  referencedFunctions?: string[];
  references: string[];
  published: string | null;
  modified: string | null;
  lockfile: string;
  /** Set when .oxaudit/advisory-policy.json (or --advisory-policy) dismisses it. */
  review?: AdvisoryReview;
}

/** Why an advisory policy dismissed a dependency or image advisory. */
export interface AdvisoryReview {
  state: "falsePositive" | "acceptedRisk" | "suppressed";
  reason: string;
  expiresAt?: string | null;
}

export interface DepScanSummary {
  inventoryNotes?: string[];
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
  /** Local matching limits or invalid offline receipts discarded before selecting valid evidence. */
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
  packages: number | null;
  parseError?: string | null;
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
  /** Limits for Template scans against live targets. */
  liveScan: LiveScanSettings;
}

/**
 * Live-target scan limits. Values outside their ranges are clamped when a
 * scan uses them; an invalid proxy fails that scan. The per-run
 * authorization acknowledgement is never stored in settings.
 */
export interface LiveScanSettings {
  /** Requests per second across the run, 1 to 1000 (default 50). */
  requestsPerSecond: number;
  /** Requests in flight to one host, 1 to 100 (default 10). */
  perHostConcurrency: number;
  /** Timeout of one request in seconds, 1 to 120 (default 10). */
  timeoutSeconds: number;
  /** Response cap per request in KiB, 1 to 32768 (default 4096). */
  maxResponseKb: number;
  /** Requests per run (default 100000); reaching it makes the run incomplete. */
  maxRequests: number;
  /** Explicit http:// or https:// proxy for HTTP templates; null for direct connections. */
  proxy: string | null;
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
  /** Set when an advisory policy (--advisory-policy) dismisses it. */
  review?: AdvisoryReview;
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

/** Historical evidence is indexed by Git objects, separately from the working tree. */
export interface HistoryScanResult {
  /** Optional only for compatibility with older command results. */
  runId?: string;
  state?: "completed" | "incomplete" | "cancelled" | "failed";
  target?: string;
  durationMs?: number;
  gitContext?: {
    headBefore: string | null;
    headAfter: string | null;
    refsBefore: Array<{ name: string; oid: string }>;
    refsAfter: Array<{ name: string; oid: string }>;
    refsCompleteAfter: boolean;
    contextChanged: boolean | null;
  };
  blobs?: Array<{ oid: string; path: string; sizeBytes: number; contentSha256: string }>;
  findingBlobIds?: Record<string, string>;
  findings: Finding[];
  blobsScanned: number;
  blobsSkipped: number;
  truncated: boolean;
  limitNote: string | null;
  /** Present only when live validation was opted into for this run. */
  validation: HistoryValidationSummary | null;
}

// ---------------------------------------------------------------- signature packs and YARA

export type SignaturePackKind = "yara" | "nuclei";

/** A rule file or rule left out of a pack, with the reason. */
export interface SignaturePackSkip {
  file: string;
  line: number | null;
  message: string;
}

/** What importing a pack would do; nothing is written. */
export interface SignaturePackPreview {
  kind: SignaturePackKind;
  fileCount: number;
  ignoredCount: number;
  ruleCount: number;
  skipped: SignaturePackSkip[];
  contentSha256: string;
  /** Recognised from a LICENSE/COPYING file in the pack root; the user confirms it. */
  detectedLicense: string | null;
  totalBytes: number;
  /** Nuclei packs: supported templates per protocol; null for YARA packs. */
  protocols: SignaturePackProtocols | null;
  /** Nuclei packs: templates that load but that oxAudit cannot evaluate (each is in `skipped`). */
  notEvaluatedCount: number;
}

/** Supported templates of a pack per protocol; a template with two protocols counts under each. */
export interface SignaturePackProtocols {
  http: number;
  dns: number;
  tcp: number;
  ssl: number;
  file: number;
}

export interface InstallSignaturePackRequest {
  kind: SignaturePackKind;
  /** A rule file, a folder, or a .zip. */
  path: string;
  name: string;
  license: string;
  version?: string;
  source?: string;
  authors?: string;
}

export interface InstalledSignaturePack {
  id: string;
  kind: SignaturePackKind;
  name: string;
  version: string;
  license: string;
  source: string;
  authors: string;
  contentSha256: string;
  fileCount: number;
  ruleCount: number;
  skipped: SignaturePackSkip[];
  enabled: boolean;
  installedAt: string;
  protocols: SignaturePackProtocols | null;
  notEvaluatedCount: number;
}

export interface YaraScanRequest {
  path: string;
  /** Omit to apply every enabled YARA pack; an empty list applies none. */
  packIds?: string[];
  /** One-off rule files or folders that are not installed. */
  extraRulePaths?: string[];
  maxFileSizeMb?: number;
  operationId?: string;
}

export interface YaraStringMatch {
  identifier: string;
  offset: number;
  length: number;
  /** For a rule that reports secrets, only the first 4 bytes (or none). */
  excerptHex: string;
  /** Set when the rule reports secrets and the excerpt was masked. */
  excerptMasked?: boolean;
}

export interface YaraMatchRow {
  id: string;
  /** Relative to the scan target, forward slashes. */
  path: string;
  filePath: string;
  sha256: string;
  rule: string;
  namespace: string;
  pack: string;
  ruleId: string;
  tags: string[];
  severity: "info" | "low" | "medium" | "high" | "critical";
  meta: Array<[string, string | number | boolean]>;
  strings: YaraStringMatch[];
  stringsTruncated: number;
}

export interface YaraSkippedFile {
  path: string;
  reason: string;
}

export interface YaraPackInfo {
  id: string;
  name: string;
  license: string;
  contentSha256: string;
  ruleCount: number;
}

export interface YaraRuleSkip {
  pack: string;
  file: string;
  line: number | null;
  message: string;
}

export interface YaraScanResult {
  runId: string;
  target: string;
  /** "incomplete" when a file timed out, a pack failed its integrity check, or a cap was hit. */
  state: "completed" | "incomplete";
  filesScanned: number;
  bytesScanned: number;
  matches: YaraMatchRow[];
  matchesDropped: number;
  skipped: YaraSkippedFile[];
  skippedDropped: number;
  packs: YaraPackInfo[];
  rulesCompiled: number;
  rulesSkipped: YaraRuleSkip[];
  rulesSkippedTotal: number;
  notes: string[];
  durationMs: number;
}

// ---------------------------------------------------------------- template scans

export interface TemplateAuthorization {
  acknowledged: boolean;
  statement: string;
}

/** Exactly one of `path` and a non-empty `targets` must be given. */
export interface TemplateScanRequest {
  /** A local file or folder, scanned with `file` templates. */
  path?: string;
  /** Live targets (URL, host, host:port, IP, CIDR). Needs `authorization.acknowledged`. */
  targets?: string[];
  authorization?: TemplateAuthorization;
  /** Omit to apply every enabled Nuclei pack; an empty list applies none. */
  packIds?: string[];
  /** One-off template files or folders that are not installed. */
  extraTemplatePaths?: string[];
  /** Run only templates with any of these tags. */
  tags?: string[];
  excludeTags?: string[];
  severities?: Array<"info" | "low" | "medium" | "high" | "critical">;
  templateIds?: string[];
  /** Templates tagged `intrusive` or `fuzz`. `dos` templates never run. */
  includeIntrusive?: boolean;
  /** Live scans: requests per second overall. */
  rateLimit?: number;
  maxFileSizeMb?: number;
  operationId?: string;
}

export interface TemplateLineRow {
  line: number;
  startColumn: number;
  endColumn: number;
  /** Capped; masked for templates that report credentials. */
  text: string;
}

export interface TemplateClassification {
  cveId: string[];
  cweId: string[];
  cvssScore: number | null;
}

export interface TemplateMatchRow {
  id: string;
  templateId: string;
  /** `<pack>/<templateId>`. */
  ruleId: string;
  name: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  tags: string[];
  pack: string;
  protocol: "file" | "http" | "dns" | "tcp" | "ssl";
  /** The file path or live endpoint that matched. */
  matchedAt: string;
  /** File matches: relative to the scan target, forward slashes. */
  filePath?: string;
  lines: TemplateLineRow[];
  matcherNames: string[];
  /** Extractor name (empty when unnamed) and its values (masked for credential templates). */
  extracted: Array<[string, string[]]>;
  classification: TemplateClassification;
  description: string;
  reference: string[];
  remediation: string;
  /** Live matches: bounded, redacted request and response excerpts. Always null for file matches. */
  exchange: TemplateExchange | null;
}

export interface TemplateExchange {
  protocol: "http" | "dns" | "tcp" | "ssl";
  /** The target as the user typed it. */
  target: string;
  /** Credential-bearing header values are "[REDACTED]". */
  request: string;
  /** Withheld for templates that report credentials. */
  responseExcerpt: string;
  responseTruncated: boolean;
}

/** The authorization a live scan was started with; recorded per run, never remembered. */
export interface TemplateAuthorizationRecord {
  acknowledged: boolean;
  statement: string;
  acknowledgedAtMs: number;
}

export interface TemplateResolvedHost {
  host: string;
  addresses: string[];
}

export interface TemplateUnreachableTarget {
  target: string;
  reason: string;
}

export interface TemplateNotEvaluatedRow {
  /** Empty when the file did not load as a template. */
  templateId: string;
  pack: string;
  /** Path inside the pack. */
  file: string;
  protocol?: string;
  target?: string;
  reason: string;
}

export interface TemplatePackInfo {
  id: string;
  name: string;
  license: string;
  contentSha256: string;
  templateCount: number;
}

export interface TemplateSkippedFile {
  path: string;
  reason: string;
}

export interface TemplateScanResult {
  runId: string;
  mode: "path" | "targets";
  target: string;
  /** "incomplete" when a pack failed its integrity check or a cap was hit. Templates not evaluated do not make a run incomplete. */
  state: "completed" | "incomplete";
  matches: TemplateMatchRow[];
  matchesDropped: number;
  notEvaluated: TemplateNotEvaluatedRow[];
  notEvaluatedDropped: number;
  packs: TemplatePackInfo[];
  templatesLoaded: number;
  templatesRun: number;
  filesScanned: number;
  bytesScanned: number;
  skipped: TemplateSkippedFile[];
  requestsSent: number;
  requestsRefused: number;
  /** Live scans: hosts (never URLs) refused by scope; nothing was sent to them. */
  refusedHosts: string[];
  /** Live scans: each host name and the addresses pinned for the run. */
  resolved: TemplateResolvedHost[];
  /** Live scans: targets that could not be resolved or reached (not evaluated). */
  unreachableTargets: TemplateUnreachableTarget[];
  /** Live scans: the recorded authorization; null for local scans. */
  authorization: TemplateAuthorizationRecord | null;
  notes: string[];
  durationMs: number;
}
