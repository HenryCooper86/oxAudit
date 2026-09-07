import { create } from "zustand";
import { parseSelectedProject } from "../features/project-home/history";
import type { AiReadiness } from "./settingsRequests";
import type { AppSettings, DependencyScanResult } from "./types";
import type { AssistantHandoff, Page, WorkbenchStatus } from "./workbench";

export interface RecentScan {
  id: string;
  kind: "source" | "deps";
  path: string;
  at: string;
  findings: number;
  critical: number;
  high: number;
}

interface AppStore {
  page: Page;
  setPage: (p: Page) => void;
  settings: AppSettings | null;
  setSettings: (s: AppSettings) => void;
  aiReadiness: AiReadiness;
  setAiReadiness: (readiness: AiReadiness) => void;
  settingsLoadError: boolean;
  setSettingsLoadError: (failed: boolean) => void;
  selectedProject: string | null;
  setSelectedProject: (path: string | null) => void;
  projectHandoff: {
    path: string;
    page: "source-scan" | "deps-scan";
    runId?: string;
    dependencyResult?: DependencyScanResult;
    version: number;
  } | null;
  openProject: (
    path: string,
    page: "source-scan" | "deps-scan",
    runId?: string,
    dependencyResult?: DependencyScanResult,
  ) => void;
  activeProject: string | null;
  setActiveProject: (p: string | null) => void;
  assistantHandoff: AssistantHandoff | null;
  openAssistant: (handoff: AssistantHandoff) => void;
  clearAssistantHandoff: () => void;
  recentScans: RecentScan[];
  addRecentScan: (r: RecentScan) => void;
  pageStatus: Partial<Record<Page, WorkbenchStatus>>;
  setPageStatus: (page: Page, status: WorkbenchStatus) => void;
  clearPageStatus: (page: Page) => void;
}

const RECENT_KEY = "vc.recentScans";

function loadRecent(): RecentScan[] {
  try {
    return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
  } catch {
    return [];
  }
}

export const useAppStore = create<AppStore>((set) => ({
  page: "dashboard",
  setPage: (page) => set({ page }),
  settings: null,
  setSettings: (settings) => set({ settings }),
  aiReadiness: { status: "loading", version: 0 },
  setAiReadiness: (aiReadiness) => set({ aiReadiness }),
  settingsLoadError: false,
  setSettingsLoadError: (settingsLoadError) => set({ settingsLoadError }),
  selectedProject: (() => {
    try {
      return parseSelectedProject(localStorage.getItem("vc.selectedProject"));
    } catch {
      return null;
    }
  })(),
  setSelectedProject: (selectedProject) => {
    try {
      localStorage.setItem(
        "vc.selectedProject",
        JSON.stringify({ version: 1, path: selectedProject }),
      );
    } catch {
      /* Preference storage may be unavailable. */
    }
    set({ selectedProject });
  },
  projectHandoff: null,
  openProject: (path, page, runId, dependencyResult) =>
    set((state) => ({
      page,
      projectHandoff: {
        path,
        page,
        runId,
        dependencyResult,
        version: (state.projectHandoff?.version ?? 0) + 1,
      },
    })),
  activeProject: null,
  setActiveProject: (activeProject) => set({ activeProject }),
  assistantHandoff: null,
  openAssistant: (assistantHandoff) =>
    set({ assistantHandoff, page: "assistant" }),
  clearAssistantHandoff: () => set({ assistantHandoff: null }),
  recentScans: loadRecent(),
  addRecentScan: (r) =>
    set((s) => {
      const recentScans = [
        r,
        ...s.recentScans.filter((x) => x.id !== r.id),
      ].slice(0, 12);
      try {
        localStorage.setItem(RECENT_KEY, JSON.stringify(recentScans));
      } catch {
        /* ignore */
      }
      return { recentScans };
    }),
  pageStatus: {},
  setPageStatus: (page, status) =>
    set((state) => ({ pageStatus: { ...state.pageStatus, [page]: status } })),
  clearPageStatus: (page) =>
    set((state) => {
      const pageStatus = { ...state.pageStatus };
      delete pageStatus[page];
      return { pageStatus };
    }),
}));

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------

export interface Toast {
  id: string;
  kind: "info" | "success" | "error";
  message: string;
}

interface ToastStore {
  toasts: Toast[];
  push: (kind: Toast["kind"], message: string) => void;
  dismiss: (id: string) => void;
}

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],
  push: (kind, message) => {
    const id = crypto.randomUUID();
    set((s) => ({ toasts: [...s.toasts, { id, kind, message }] }));
    setTimeout(() => {
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    }, 5000);
  },
  dismiss: (id) =>
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));
