export type Page =
  | "dashboard"
  | "portfolio"
  | "source-scan"
  | "history-scan"
  | "deps-scan"
  | "binary-scan"
  | "inventory"
  | "rule-library"
  | "quality-lab"
  | "data-sources"
  | "export-center"
  | "verification"
  | "compliance-center"
  | "report-studio"
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
  portfolio: { title: "Portfolio", group: "Overview" },
  "source-scan": { title: "Source Scan", group: "Scanning" },
  "history-scan": { title: "History Scan", group: "Scanning" },
  "deps-scan": { title: "Dependencies", group: "Scanning" },
  "binary-scan": { title: "Binary Scan", group: "Scanning" },
  inventory: { title: "Inventory", group: "System" },
  "rule-library": { title: "Rule Library", group: "System" },
  "quality-lab": { title: "Quality Lab", group: "System" },
  "data-sources": { title: "Data Sources", group: "System" },
  "export-center": { title: "Export Center", group: "System" },
  verification: { title: "Verification", group: "System" },
  "compliance-center": { title: "Compliance Center", group: "System" },
  "report-studio": { title: "Report Studio", group: "System" },
  "cve-research": { title: "CVE Research", group: "Research" },
  assistant: { title: "AI Assistant", group: "Research" },
  settings: { title: "Settings", group: "System" },
};
