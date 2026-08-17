import {
  Bot,
  Boxes,
  Bug,
  FileSearch,
  LayoutDashboard,
  Settings,
  ShieldHalf,
} from "lucide-react";
import { useAppStore, type Page } from "../lib/stores";

const NAV: { page: Page; label: string; icon: typeof Bug }[] = [
  { page: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { page: "source-scan", label: "Source Scan", icon: FileSearch },
  { page: "deps-scan", label: "Dependencies", icon: Boxes },
  { page: "cve-research", label: "CVE Research", icon: Bug },
  { page: "assistant", label: "AI Assistant", icon: Bot },
  { page: "settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const { page, setPage, aiReady } = useAppStore();
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-ink-800 bg-ink-900">
      <div className="flex items-center gap-2.5 px-4 pb-4 pt-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-teal-500 to-emerald-600 shadow-lg shadow-teal-900/40">
          <ShieldHalf size={17} className="text-ink-950" />
        </div>
        <div>
          <div className="text-sm font-bold tracking-tight text-slate-100">VulnCompanion</div>
          <div className="text-[10px] uppercase tracking-widest text-slate-500">
            vuln research
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 px-2.5">
        {NAV.map(({ page: p, label, icon: Icon }) => (
          <button
            key={p}
            onClick={() => setPage(p)}
            className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] font-medium transition-colors ${
              page === p
                ? "bg-ink-750 text-teal-300"
                : "text-slate-400 hover:bg-ink-850 hover:text-slate-200"
            }`}
          >
            <Icon size={15} />
            {label}
          </button>
        ))}
      </nav>

      <div className="border-t border-ink-800 px-4 py-3.5">
        <div className="flex items-center gap-2 text-[11px] text-slate-500">
          <span
            className={`h-2 w-2 rounded-full ${
              aiReady === null ? "bg-slate-600" : aiReady ? "bg-emerald-500" : "bg-red-500"
            }`}
          />
          AI engine {aiReady === null ? "unconfigured" : aiReady ? "ready" : "offline"}
        </div>
      </div>
    </aside>
  );
}
