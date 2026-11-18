export type Page =
  | "dashboard"
  | "portfolio"
  | "source-scan"
  | "history-scan"
  | "deps-scan"
  | "binary-scan"
  | "image-scan"
  | "yara-scan"
  | "template-scan"
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

/**
 * Sidebar groups, in display order. The shell follows oxFuzz's shape: a short
 * primary group first, then the scanning pipeline, then what scans produce,
 * then reference intelligence and detection quality. Settings sits in the
 * sidebar footer under "System".
 */
export type NavigationGroup =
  | "Workspace"
  | "Scanning"
  | "Results"
  | "Intelligence"
  | "Quality"
  | "System";

export interface PageMeta {
  title: string;
  group: NavigationGroup;
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

/** The sidebar body, top to bottom. Settings is the footer item. */
export const NAVIGATION_SECTIONS: ReadonlyArray<{ group: Exclude<NavigationGroup, "System">; pages: readonly Page[] }> = [
  { group: "Workspace", pages: ["dashboard", "portfolio", "assistant"] },
  {
    group: "Scanning",
    pages: ["source-scan", "history-scan", "deps-scan", "binary-scan", "image-scan", "yara-scan", "template-scan"],
  },
  {
    group: "Results",
    pages: ["inventory", "verification", "export-center", "report-studio", "compliance-center"],
  },
  { group: "Intelligence", pages: ["cve-research", "advisory-database", "data-sources", "vex-trust"] },
  { group: "Quality", pages: ["rule-library", "quality-lab"] },
];

export const PAGE_META: Record<Page, PageMeta> = {
  dashboard: { title: "Dashboard", group: "Workspace" },
  portfolio: { title: "Portfolio", group: "Workspace" },
  assistant: { title: "AI Assistant", group: "Workspace" },
  "source-scan": { title: "Source Scan", group: "Scanning" },
  "history-scan": { title: "History Scan", group: "Scanning" },
  "deps-scan": { title: "Dependencies", group: "Scanning" },
  "binary-scan": { title: "Binary Scan", group: "Scanning" },
  "image-scan": { title: "Image Scan", group: "Scanning" },
  "yara-scan": { title: "YARA Scan", group: "Scanning" },
  "template-scan": { title: "Template Scan", group: "Scanning" },
  inventory: { title: "Inventory", group: "Results" },
  verification: { title: "Verification", group: "Results" },
  "export-center": { title: "Export Center", group: "Results" },
  "report-studio": { title: "Report Studio", group: "Results" },
  "compliance-center": { title: "Compliance Center", group: "Results" },
  "cve-research": { title: "CVE Research", group: "Intelligence" },
  "advisory-database": { title: "Advisory Database", group: "Intelligence" },
  "data-sources": { title: "Data Sources", group: "Intelligence" },
  "vex-trust": { title: "VEX Trust", group: "Intelligence" },
  "rule-library": { title: "Rule Library", group: "Quality" },
  "quality-lab": { title: "Quality Lab", group: "Quality" },
  settings: { title: "Settings", group: "System" },
};

/**
 * Pages that do not render a `ToolPage`, and therefore no `h1` of their own.
 * The shell header renders their title as the page's single `h1`; every other
 * page's `h1` is its ToolPage title.
 */
export const SHELL_HEADING_PAGES: ReadonlySet<Page> = new Set<Page>(["assistant"]);
