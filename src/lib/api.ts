import { invoke } from "@tauri-apps/api/core";
import type {
  BulkReviewOutcome,
  Diagnostics,
  AiStatus,
  AppSettings,
  SaveSettingsRequest,
  SaveSettingsResult,
  TestAiRequest,
  ChatRequest,
  ChatResponse,
  CveDetail,
  CveItem,
  CveSearchResult,
  CanonicalRun,
  CanonicalRunKind,
  RuleLibraryPackStatus,
  InstalledRulePack,
  RulePackValidationPreview,
  QualityStatus,
  DataSourceStatus,
  ExportFormat,
  ExportPreview,
  InventoryView,
  ImportPreview,
  CanonicalFinding,
  VerificationRecord,
  VerificationResult,
  DependencyScanResult,
  Finding,
  GitContext,
  HistoryScanResult,
  LockfileInfo,
  ScanOptions,
  ScanRunDetail,
  RecheckSourceResult,
  ScanRunSummary,
  ProjectContext,
  RecentProject,
  ReviewRecord,
  ReviewRequest,
  SessionInfo,
  StoredMessage,
  BinaryScanRequest,
  BinaryScanResult,
  BinaryScannersStatus,
  StreamStarted,
  TodoItem,
  UsageSummary,
  ComplianceProfile,
  ComplianceAssessment,
  ComplianceAssessmentView,
  ComplianceReadinessStatus,
  ComplianceReview,
  RunComplianceRequest,
  ComplianceReportRequest,
  ComplianceReportPreview,
  ComplianceReportReceipt,
} from "./types";

export const api = {
  scanProject: (options: ScanOptions) =>
    invoke<ScanRunDetail>("scan_project", { options }),
  recheckSourceRun: (originalRunId: string, projectId: string) =>
    invoke<RecheckSourceResult>("recheck_source_run", { originalRunId, projectId }),
  cancelScan: () => invoke<void>("cancel_scan"),
  scanHistorySecrets: (path: string, validateSecrets = false) =>
    invoke<HistoryScanResult>("scan_history_secrets", { path, validateSecrets }),
  inspectSourceProject: (path: string) =>
    invoke<ProjectContext>("inspect_source_project", { path }),
  listSourceProjects: (limit = 12) =>
    invoke<RecentProject[]>("list_source_projects", { limit }),
  listSourceRuns: (projectId: string, limit = 50) =>
    invoke<ScanRunSummary[]>("list_source_runs", { projectId, limit }),
  compareSourceRuns: (currentRunId: string, baselineRunId: string, requireValidPolicy = false) =>
    invoke<Finding[]>("compare_source_runs", { currentRunId, baselineRunId, ...(requireValidPolicy ? { requireValidPolicy } : {}) }),
  inspectSourceGit: (path: string, baseReference: string) =>
    invoke<GitContext>("inspect_source_git", { path, baseReference }),
  loadSourceRun: (runId: string) =>
    invoke<ScanRunDetail>("load_source_run", { runId }),
  retrySourceRunSave: (retryToken: string) =>
    invoke<ScanRunDetail>("retry_source_run_save", { retryToken }),
  listCanonicalRuns: (kind?: CanonicalRunKind, limit = 50) =>
    invoke<CanonicalRun[]>("list_canonical_runs", {
      kind: kind ?? null,
      limit,
    }),
  loadCanonicalProjection: <T>(runId: string) =>
    invoke<T>("load_canonical_projection", { runId }),
  ruleLibraryStatus: () =>
    invoke<RuleLibraryPackStatus[]>("rule_library_status"),
  validateRulePack: (path: string) =>
    invoke<RulePackValidationPreview>("validate_rule_pack", { path }),
  installRulePack: (path: string) =>
    invoke<InstalledRulePack>("install_rule_pack", { path }),
  listInstalledRulePacks: () =>
    invoke<InstalledRulePack[]>("list_installed_rule_packs"),
  setRulePackEnabled: (id: string, enabled: boolean) =>
    invoke<void>("set_rule_pack_enabled", { id, enabled }),
  removeRulePack: (id: string) =>
    invoke<void>("remove_rule_pack", { id }),
  qualityStatus: () => invoke<QualityStatus>("quality_status"),
  listDataSources: () => invoke<DataSourceStatus[]>("list_data_sources"),
  refreshDataSource: (providerId: string) =>
    invoke<DataSourceStatus>("refresh_data_source", { providerId }),
  loadInventory: (runId: string) =>
    invoke<InventoryView>("load_inventory", { runId }),
  previewReportImport: (path: string) =>
    invoke<ImportPreview>("preview_report_import", { path }),
  importInventoryReport: (path: string, expectedSha256: string) =>
    invoke<CanonicalRun>("import_inventory_report", { path, expectedSha256 }),
  importExternalReport: (path: string, expectedSha256: string) =>
    invoke<CanonicalRun>("import_external_report", { path, expectedSha256 }),
  previewRunExport: (runId: string, format: ExportFormat) =>
    invoke<ExportPreview>("preview_run_export", { runId, format }),
  writeRunExport: (runId: string, format: ExportFormat, outputPath: string) =>
    invoke<void>("write_run_export", { runId, format, outputPath }),
  listVerificationClaims: (runId?: string) =>
    invoke<CanonicalFinding[]>("list_verification_claims", { runId: runId ?? null }),
  listVerifications: (findingId?: string) =>
    invoke<VerificationRecord[]>("list_verifications", { findingId: findingId ?? null }),
  verifyFinding: (
    findingId: string,
    verifierId: string,
    result: VerificationResult,
    limitation: string,
  ) => invoke<VerificationRecord>("verify_finding", { findingId, verifierId, result, limitation }),
  saveFindingReview: (request: ReviewRequest) =>
    invoke<ReviewRecord>("save_finding_review", { request }),
  /** Whether a usable cve-bin-tool is installed, and which copy we would run. */
  binaryToolStatus: () => invoke<BinaryScannersStatus>("binary_tool_status"),
  scanBinaries: (request: BinaryScanRequest, useGrype: boolean) =>
    invoke<BinaryScanResult>("scan_binaries", { request, useGrype }),
  cancelBinaryScan: () => invoke<void>("cancel_binary_scan"),
  /** Force `--update now`; the only escape from cve-bin-tool's stale-cache trap. */
  refreshBinaryDatabase: () => invoke<void>("refresh_binary_database"),
  openScanFinding: (root: string, relativePath: string, line: number, column: number) =>
    invoke<void>("open_scan_finding", { root, relativePath, line, column }),
  scanDependencies: (path: string, offline = false) =>
    invoke<DependencyScanResult>("scan_dependencies", { path, offline }),
  cancelDependencyScan: () => invoke<void>("cancel_dependency_scan"),
  findLockfiles: (path: string) =>
    invoke<LockfileInfo[]>("find_lockfiles", { path }),
  searchCves: (
    query: string,
    startIndex: number,
    perPage: number,
    recentDays: number | null,
  ) =>
    invoke<CveSearchResult>("search_cves", {
      query,
      startIndex,
      perPage,
      recentDays,
    }),
  cveDetail: (id: string) => invoke<CveDetail>("cve_detail", { id }),
  osvPackageVulns: (ecosystem: string, name: string) =>
    invoke<unknown[]>("osv_package_vulns", { ecosystem, name }),
  streamChat: (request: ChatRequest, runId?: string) =>
    invoke<StreamStarted>("stream_chat", {
      request,
      ...(runId ? { runId } : {}),
    }),
  cancelChat: (runId: string) => invoke<void>("cancel_chat", { runId }),
  /** Queue a message for a run already in flight. `false` = run already ended. */
  steerChat: (runId: string, message: string) =>
    invoke<boolean>("steer_chat", { runId, message }),
  /** The agent's todo list for a conversation, for restoring it between turns. */
  todoList: (conversationId: string) =>
    invoke<TodoItem[]>("todo_list", { conversationId }),
  respondPermission: (requestId: string, approve: boolean) =>
    invoke<void>("respond_permission", { requestId, approve }),
  respondInteraction: (requestId: string, answers: unknown) =>
    invoke<void>("respond_interaction", { requestId, answers }),
  setActiveProject: (path: string | null) =>
    invoke<void>("set_active_project", { path }),
  getConversationUsage: (conversationId: string) =>
    invoke<UsageSummary>("get_conversation_usage", { conversationId }),
  getTotalUsage: () => invoke<UsageSummary>("get_total_usage"),
  sessionList: () => invoke<SessionInfo[]>("session_list"),
  sessionCreate: (title?: string | null, projectPath?: string | null) =>
    invoke<SessionInfo>("session_create", { title, projectPath }),
  sessionGetMessages: (sessionId: string) =>
    invoke<StoredMessage[]>("session_get_messages", { sessionId }),
  sessionAppend: (sessionId: string, message: StoredMessage) =>
    invoke<SessionInfo>("session_append", { sessionId, message }),
  sessionRename: (sessionId: string, title: string) =>
    invoke<void>("session_rename", { sessionId, title }),
  sessionDelete: (sessionId: string) => invoke<void>("session_delete", { sessionId }),
  sessionTruncate: (sessionId: string, keepCount: number) =>
    invoke<void>("session_truncate", { sessionId, keepCount }),
  researchCve: (cve: CveItem, osv: unknown | null) =>
    invoke<ChatResponse>("research_cve", { cve, osv }),
  testAi: () => invoke<AiStatus>("test_ai"),
  testAiWith: (request: TestAiRequest) =>
    invoke<AiStatus>("test_ai_with", { request }),
  loadSettings: () => invoke<AppSettings>("load_settings"),
  saveSettings: (request: SaveSettingsRequest) =>
    invoke<SaveSettingsResult>("save_settings", { request }),
  listComplianceProfiles: () =>
    invoke<ComplianceProfile[]>("list_compliance_profiles"),
  runComplianceAssessment: (request: RunComplianceRequest) =>
    invoke<ComplianceAssessment[]>("run_compliance_assessment", { request }),
  listComplianceAssessments: (limit = 50) =>
    invoke<ComplianceAssessment[]>("list_compliance_assessments", { limit }),
  loadComplianceAssessment: (assessmentId: string) =>
    invoke<ComplianceAssessmentView>("load_compliance_assessment", { assessmentId }),
  saveComplianceReview: (
    assessmentId: string,
    controlId: string,
    status: ComplianceReadinessStatus,
    note: string,
    author: string,
  ) => invoke<ComplianceReview>("save_compliance_review", { request: { assessmentId, controlId, status, note, author } }),
  previewComplianceReport: (request: ComplianceReportRequest) =>
    invoke<ComplianceReportPreview>("preview_compliance_report", { request }),
  writeComplianceReport: (request: ComplianceReportRequest, outputPath: string) =>
    invoke<ComplianceReportReceipt>("write_compliance_report", { request: { ...request, outputPath } }),
  collectDiagnostics: () => invoke<Diagnostics>("collect_diagnostics"),
  saveFindingReviews: (requests: ReviewRequest[]) =>
    invoke<BulkReviewOutcome>("save_finding_reviews", { requests }),

};
