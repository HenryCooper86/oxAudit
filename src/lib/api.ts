import { invoke } from "@tauri-apps/api/core";
import type {
  AiSettings,
  AiStatus,
  AppSettings,
  ChatRequest,
  ChatResponse,
  CveDetail,
  CveItem,
  CveSearchResult,
  DependencyScanResult,
  Finding,
  LockfileInfo,
  ScanOptions,
  ScanResult,
  SessionInfo,
  StoredMessage,
  StreamStarted,
  UsageSummary,
} from "./types";

export const api = {
  scanProject: (options: ScanOptions) =>
    invoke<ScanResult>("scan_project", { options }),
  cancelScan: () => invoke<void>("cancel_scan"),
  scanDependencies: (path: string) =>
    invoke<DependencyScanResult>("scan_dependencies", { path }),
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
  chat: (request: ChatRequest) => invoke<ChatResponse>("chat", { request }),
  streamChat: (request: ChatRequest) =>
    invoke<StreamStarted>("stream_chat", { request }),
  cancelChat: (runId: string) => invoke<void>("cancel_chat", { runId }),
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
  analyzeFinding: (finding: Finding) =>
    invoke<ChatResponse>("analyze_finding", { finding }),
  researchCve: (cve: CveItem, osv: unknown | null) =>
    invoke<ChatResponse>("research_cve", { cve, osv }),
  testAi: () => invoke<AiStatus>("test_ai"),
  testAiWith: (settings: AiSettings) =>
    invoke<AiStatus>("test_ai_with", { settings }),
  loadSettings: () => invoke<AppSettings>("load_settings"),
  saveSettings: (settings: AppSettings) =>
    invoke<void>("save_settings", { settings }),
  getAiSettings: () => invoke<AiSettings>("get_ai_settings"),
};
