import { create } from "zustand";
import type { AppSettings } from "./types";

export type Page =
  | "dashboard"
  | "source-scan"
  | "deps-scan"
  | "cve-research"
  | "assistant"
  | "settings";

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
  aiReady: boolean | null;
  setAiReady: (v: boolean | null) => void;
  activeProject: string | null;
  setActiveProject: (p: string | null) => void;
  recentScans: RecentScan[];
  addRecentScan: (r: RecentScan) => void;
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
  aiReady: null,
  setAiReady: (aiReady) => set({ aiReady }),
  activeProject: null,
  setActiveProject: (activeProject) => set({ activeProject }),
  recentScans: loadRecent(),
  addRecentScan: (r) =>
    set((s) => {
      const recentScans = [r, ...s.recentScans.filter((x) => x.id !== r.id)].slice(0, 12);
      try {
        localStorage.setItem(RECENT_KEY, JSON.stringify(recentScans));
      } catch {
        /* ignore */
      }
      return { recentScans };
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
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));
