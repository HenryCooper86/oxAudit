import { create } from "zustand";
import { parseSelectedProject } from "../features/project-home/history";
import type { AiReadiness } from "./settingsRequests";
import type { AppSettings, DependencyScanResult } from "./types";
import type { AssistantHandoff, Page, WorkbenchStatus } from "./workbench";
import { DEFAULT_SETTINGS_SECTION, type SettingsSectionId } from "./settingsSections";
import { newId } from "./ids";

interface AppStore {
  page: Page;
  setPage: (p: Page) => void;
  /** The Settings sub-page being shown while `page === "settings"`. */
  settingsSection: SettingsSectionId;
  setSettingsSection: (section: SettingsSectionId) => void;
  /** Where "Back" in Settings returns to: the page Settings was opened from. */
  settingsReturnPage: Page;
  /** Open Settings, optionally on a given section (deep links: "ai", "scan-defaults"). */
  openSettings: (section?: SettingsSectionId) => void;
  /** Leave Settings for the page it was opened from. */
  closeSettings: () => void;
  exportHandoff: { runId: string } | null;
  openExport: (runId: string) => void;
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
  /**
   * Set when something outside Project home (the sidebar's "Open project" in
   * server mode, where no native folder picker exists) asks for the project
   * folder field. Project home focuses the field and clears the request.
   */
  projectFieldRequest: number | null;
  requestProjectField: () => void;
  consumeProjectFieldRequest: () => void;
  assistantHandoff: AssistantHandoff | null;
  openAssistant: (handoff: AssistantHandoff) => void;
  clearAssistantHandoff: () => void;
  pageStatus: Partial<Record<Page, WorkbenchStatus>>;
  setPageStatus: (page: Page, status: WorkbenchStatus) => void;
  clearPageStatus: (page: Page) => void;
}

export const useAppStore = create<AppStore>((set) => ({
  page: "dashboard",
  setPage: (page) =>
    set((state) =>
      page === "settings" && state.page !== "settings"
        ? { page, settingsReturnPage: state.page }
        : { page },
    ),
  settingsSection: DEFAULT_SETTINGS_SECTION,
  setSettingsSection: (settingsSection) => set({ settingsSection }),
  settingsReturnPage: "dashboard",
  openSettings: (section) =>
    set((state) => ({
      page: "settings",
      settingsReturnPage: state.page === "settings" ? state.settingsReturnPage : state.page,
      ...(section ? { settingsSection: section } : {}),
    })),
  closeSettings: () =>
    set((state) => ({
      page: state.settingsReturnPage === "settings" ? "dashboard" : state.settingsReturnPage,
    })),
  exportHandoff: null,
  openExport: (runId) => set({ page: "export-center", exportHandoff: { runId } }),
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
  projectFieldRequest: null,
  requestProjectField: () =>
    set((state) => ({ page: "dashboard", projectFieldRequest: (state.projectFieldRequest ?? 0) + 1 })),
  consumeProjectFieldRequest: () => set({ projectFieldRequest: null }),
  assistantHandoff: null,
  openAssistant: (assistantHandoff) =>
    set({ assistantHandoff, page: "assistant" }),
  clearAssistantHandoff: () => set({ assistantHandoff: null }),
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
  /** Stop a toast's auto-dismiss countdown (hover or focus). */
  pause: (id: string) => void;
  /** Continue a paused countdown with the time it had left. */
  resume: (id: string) => void;
}

/** Most toasts shown at once; older ones are dropped first. */
export const MAX_TOASTS = 5;
/** Auto-dismiss delay for info and success toasts. Errors stay until dismissed. */
export const TOAST_DURATION_MS = 5000;

interface ToastTimer {
  handle: ReturnType<typeof setTimeout> | null;
  remaining: number;
  startedAt: number;
}

const toastTimers = new Map<string, ToastTimer>();

function clearToastTimer(id: string) {
  const timer = toastTimers.get(id);
  if (timer?.handle) clearTimeout(timer.handle);
  toastTimers.delete(id);
}

export const useToastStore = create<ToastStore>((set, get) => {
  const startTimer = (id: string, remaining: number) => {
    toastTimers.set(id, {
      remaining,
      startedAt: Date.now(),
      handle: setTimeout(() => get().dismiss(id), remaining),
    });
  };
  return {
    toasts: [],
    push: (kind, message) => {
      const id = newId();
      const next = [...get().toasts, { id, kind, message }];
      const dropped = next.slice(0, Math.max(0, next.length - MAX_TOASTS));
      for (const toast of dropped) clearToastTimer(toast.id);
      set({ toasts: next.slice(-MAX_TOASTS) });
      if (kind !== "error") startTimer(id, TOAST_DURATION_MS);
    },
    dismiss: (id) => {
      clearToastTimer(id);
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    },
    pause: (id) => {
      const timer = toastTimers.get(id);
      if (!timer?.handle) return;
      clearTimeout(timer.handle);
      toastTimers.set(id, {
        handle: null,
        startedAt: timer.startedAt,
        remaining: Math.max(0, timer.remaining - (Date.now() - timer.startedAt)),
      });
    },
    resume: (id) => {
      const timer = toastTimers.get(id);
      if (!timer || timer.handle) return;
      startTimer(id, Math.max(1000, timer.remaining));
    },
  };
});
