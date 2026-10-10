import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { httpInvoke, serverMode } from "./transport";

/** Desktop IPC at home, HTTP against the headless server. */
function invoke<T>(cmd: string, args?: unknown): Promise<T> {
  return serverMode
    ? httpInvoke<T>(cmd, args)
    : tauriInvoke<T>(cmd, (args ?? {}) as Parameters<typeof tauriInvoke>[1]);
}
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
  ScanScheduleRecord,
  AdvisoryDbStatus,
  AdvisoryDbUpdateReport,
  ImageScanOutcome,
  ImageScanRequest,
  ScanScheduleStatus,
  VexClaimSet,
  VexSuggestions,
  RulePackValidationPreview,
  QualityStatus,
  DataSourceStatus,
  ExportFormat,
  ExportPreview,
  InventoryView,
  ImportPreview,
  CanonicalFinding,
  ExternalBenchmarkReport,
  VerificationRecord,
  VerificationResult,
  DependencyScanResult,
  Finding,
  GitContext,
  HistoryScanResult,
  LockfileInfo,
  ScanOptions,
  ScanWorkSnapshot,
  ScanRunDetail,
  SourceRunMetadata,
  SourceFindingsQuery,
  SourceFindingsPage,
  ResultPageQuery,
  ResultPage,
  CanonicalProjectionMetadata,
  CanonicalProjectionSection,
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
  scanWorkStatus: () => invoke<ScanWorkSnapshot>("scan_work_status"),
  cancelScanWork: (operationId: string) => invoke<boolean>("cancel_scan_work", { operationId }),
  scanProject: (options: ScanOptions, operationId?: string) =>
    invoke<ScanRunDetail>("scan_project", { options, ...(operationId ? { operationId } : {}) }),
  recheckSourceRun: (originalRunId: string, projectId: string, operationId?: string) =>
    invoke<RecheckSourceResult>("recheck_source_run", { originalRunId, projectId, ...(operationId ? { operationId } : {}) }),
  cancelScan: () => invoke<void>("cancel_scan"),
  scanHistorySecrets: (path: string, validateSecrets = false, operationId?: string) =>
    invoke<HistoryScanResult>("scan_history_secrets", { path, validateSecrets, ...(operationId ? { operationId } : {}) }),
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
  loadSourceRunMetadata: (runId: string) =>
    invoke<SourceRunMetadata>("load_source_run_metadata", { runId }),
  loadSourceRunPage: (runId: string, query: SourceFindingsQuery = {}) =>
    invoke<SourceFindingsPage>("load_source_run_page", { runId, query }),
  retrySourceRunSave: (retryToken: string) =>
    invoke<ScanRunDetail>("retry_source_run_save", { retryToken }),
  listCanonicalRuns: (kind?: CanonicalRunKind, limit = 50) =>
    invoke<CanonicalRun[]>("list_canonical_runs", {
      kind: kind ?? null,
      limit,
    }),
  loadCanonicalProjection: <T>(runId: string) =>
    invoke<T>("load_canonical_projection", { runId }),
  loadCanonicalProjectionMetadata: <T>(runId: string) =>
    invoke<CanonicalProjectionMetadata<T>>("load_canonical_projection_metadata", { runId }),
  loadCanonicalProjectionPage: <T>(runId: string, section: CanonicalProjectionSection, query: ResultPageQuery = {}) =>
    invoke<ResultPage<T>>("load_canonical_projection_page", { runId, section, query }),
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
  listScanSchedules: () => invoke<ScanScheduleStatus[]>("list_scan_schedules"),
  advisoryDbStatus: (path: string) =>
    invoke<AdvisoryDbStatus>("advisory_db_status", { path }),
  advisoryDbUpdate: (path: string, ecosystems: string[], source?: string) =>
    invoke<AdvisoryDbUpdateReport>("advisory_db_update", {
      path,
      ecosystems,
      source: source ?? null,
    }),
  scanImage: (request: ImageScanRequest) =>
    invoke<ImageScanOutcome>("scan_image", { request }),
  cancelImageScan: () => invoke<void>("cancel_image_scan"),
  vexClaimSets: () => invoke<VexClaimSet[]>("vex_claim_sets"),
  vexGrantTrust: (contentSha256: string, grantedBy: string, note?: string) =>
    invoke<void>("vex_grant_trust", { contentSha256, grantedBy, note: note ?? null }),
  vexRevokeTrust: (contentSha256: string) =>
    invoke<void>("vex_revoke_trust", { contentSha256 }),
  vexSuggest: (runId: string) => invoke<VexSuggestions>("vex_suggest", { runId }),
  setScanSchedule: (
    projectId: string,
    canonicalPath: string,
    displayName: string,
    intervalHours: number,
    enabled: boolean,
  ) =>
    invoke<ScanScheduleRecord>("set_scan_schedule", {
      projectId,
      canonicalPath,
      displayName,
      intervalHours,
      enabled,
    }),
  removeScanSchedule: (projectId: string) =>
    invoke<void>("remove_scan_schedule", { projectId }),
  runScanNow: (projectId: string, canonicalPath: string) =>
    invoke<ScanRunDetail>("run_scan_now", { projectId, canonicalPath }),
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
  scanBinaries: (request: BinaryScanRequest, useGrype: boolean, operationId?: string) =>
    invoke<BinaryScanResult>("scan_binaries", { request, useGrype, ...(operationId ? { operationId } : {}) }),
  cancelBinaryScan: () => invoke<void>("cancel_binary_scan"),
  /** Force `--update now`; the only escape from cve-bin-tool's stale-cache trap. */
  refreshBinaryDatabase: (operationId?: string) => invoke<void>("refresh_binary_database", operationId ? { operationId } : undefined),
  openScanFinding: (root: string, relativePath: string, line: number, column: number) =>
    invoke<void>("open_scan_finding", { root, relativePath, line, column }),
  scanDependencies: (path: string, offline = false, advisoryDbPath: string | null = null, operationId?: string) =>
    invoke<DependencyScanResult>("scan_dependencies", { path, offline, advisoryDbPath, ...(operationId ? { operationId } : {}) }),
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
  /** Record a candidate-state review, superseding the finding's decision. */
  deleteFindingReview: (request: ReviewRequest) =>
    invoke<ReviewRecord>("delete_finding_review", { request }),
  /** Score a local OWASP Benchmark checkout (the CLI's external-benchmark). */
  externalBenchmark: (path: string) =>
    invoke<ExternalBenchmarkReport>("external_benchmark", { path }),
  listCompiledGrammars: () => invoke<string[]>("list_compiled_grammars"),
  /** The advisory database file the app manages by default. */
  defaultAdvisoryDbPath: () => invoke<string>("default_advisory_db_path"),

};
