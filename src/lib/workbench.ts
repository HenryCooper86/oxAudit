export type Page =
  | "dashboard"
  | "portfolio"
  | "source-scan"
  | "history-scan"
  | "deps-scan"
  | "binary-scan"
  | "image-scan"
  | "advisory-database"
  | "vex-trust"
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
  group: "Overview" | "Scanning" | "Research" | "Trust & quality" | "System";
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
  "image-scan": { title: "Image Scan", group: "Scanning" },
  "advisory-database": { title: "Advisory Database", group: "Trust & quality" },
  "vex-trust": { title: "VEX Trust", group: "Trust & quality" },
  inventory: { title: "Inventory", group: "Trust & quality" },
  "rule-library": { title: "Rule Library", group: "Trust & quality" },
  "quality-lab": { title: "Quality Lab", group: "Trust & quality" },
  "data-sources": { title: "Data Sources", group: "Trust & quality" },
  "export-center": { title: "Export Center", group: "Trust & quality" },
  verification: { title: "Verification", group: "Trust & quality" },
  "compliance-center": { title: "Compliance Center", group: "Trust & quality" },
  "report-studio": { title: "Report Studio", group: "Trust & quality" },
  "cve-research": { title: "CVE Research", group: "Research" },
  assistant: { title: "AI Assistant", group: "Research" },
  settings: { title: "Settings", group: "System" },
};
