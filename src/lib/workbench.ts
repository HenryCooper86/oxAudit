export type Page =
  | "dashboard"
  | "source-scan"
  | "deps-scan"
  | "cve-research"
  | "assistant"
  | "settings";

export interface PageMeta {
  title: string;
  group: "Overview" | "Scanning" | "Research" | "System";
}

export type StatusTone = "neutral" | "running" | "success" | "error";

export interface WorkbenchStatus {
  label: string;
  tone: StatusTone;
  detail?: string;
}

export interface AssistantHandoff {
  id: string;
  label: string;
  content: string;
  projectPath: string | null;
}

export const PAGE_META: Record<Page, PageMeta> = {
  dashboard: { title: "Dashboard", group: "Overview" },
  "source-scan": { title: "Source Scan", group: "Scanning" },
  "deps-scan": { title: "Dependencies", group: "Scanning" },
  "cve-research": { title: "CVE Research", group: "Research" },
  assistant: { title: "AI Assistant", group: "Research" },
  settings: { title: "Settings", group: "System" },
};
