import {
  Bot,
  Boxes,
  Bug,
  FileSearch,
  LayoutDashboard,
  Settings,
  ShieldHalf,
  X,
} from "lucide-react";
import type { JSX } from "react";
import { useAppStore } from "../lib/stores";
import type { Page } from "../lib/workbench";

type NavigationItem = {
  page: Page;
  label: string;
  icon: typeof Bug;
};

const NAVIGATION_GROUPS: { label: string; items: NavigationItem[] }[] = [
  {
    label: "Overview",
    items: [{ page: "dashboard", label: "Dashboard", icon: LayoutDashboard }],
  },
  {
    label: "Scanning",
    items: [
      { page: "source-scan", label: "Source Scan", icon: FileSearch },
      { page: "deps-scan", label: "Dependencies", icon: Boxes },
    ],
  },
  {
    label: "Research",
    items: [
      { page: "cve-research", label: "CVE Research", icon: Bug },
      { page: "assistant", label: "AI Assistant", icon: Bot },
    ],
  },
];

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }): JSX.Element {
  const page = useAppStore((state) => state.page);
  const setPage = useAppStore((state) => state.setPage);

  const selectPage = (nextPage: Page) => {
    setPage(nextPage);
    onClose();
  };

  const navigationButton = ({ page: itemPage, label, icon: Icon }: NavigationItem) => (
    <button
      key={itemPage}
      type="button"
      aria-current={page === itemPage ? "page" : undefined}
      onClick={() => selectPage(itemPage)}
      className={`flex w-full items-center gap-2.5 rounded px-3 py-2 text-left text-[13px] font-medium transition-colors ${
        page === itemPage
          ? "bg-ink-750 text-accent-300"
          : "text-stone-400 hover:bg-ink-850 hover:text-stone-100"
      }`}
    >
      <Icon aria-hidden="true" size={15} />
      <span>{label}</span>
    </button>
  );

  return (
    <>
      {open && (
        <button
          type="button"
          aria-label="Close navigation"
          onClick={onClose}
          className="fixed inset-0 z-30 bg-black/60 min-[900px]:hidden"
        />
      )}
      <aside
        aria-label="Primary navigation"
        className={`z-40 flex h-full w-52 flex-col border-r border-ink-800 bg-ink-900 transition-transform max-[900px]:fixed max-[900px]:inset-y-0 max-[900px]:left-0 ${
          open
            ? "max-[900px]:translate-x-0 max-[900px]:visible"
            : "max-[900px]:-translate-x-full max-[900px]:invisible"
        }`}
      >
        <div className="flex h-[60px] shrink-0 items-center gap-2.5 border-b border-ink-800 px-4">
          <div className="flex h-8 w-8 items-center justify-center rounded bg-accent-500 text-ink-950">
            <ShieldHalf aria-hidden="true" size={17} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-semibold tracking-tight text-stone-100">oxAudit</div>
            <div className="text-[10px] uppercase tracking-[0.16em] text-stone-500">
              security workbench
            </div>
          </div>
          <button
            type="button"
            aria-label="Close navigation"
            onClick={onClose}
            className="rounded p-1.5 text-stone-400 hover:bg-ink-800 hover:text-stone-100 min-[900px]:hidden"
          >
            <X aria-hidden="true" size={16} />
          </button>
        </div>

        <nav className="flex-1 space-y-5 overflow-y-auto px-2.5 py-4">
          {NAVIGATION_GROUPS.map((group) => (
            <div key={group.label}>
              <div className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-stone-600">
                {group.label}
              </div>
              <div className="space-y-0.5">{group.items.map(navigationButton)}</div>
            </div>
          ))}
        </nav>

        <div className="border-t border-ink-800 p-2.5">
          {navigationButton({ page: "settings", label: "Settings", icon: Settings })}
        </div>
      </aside>
    </>
  );
}
