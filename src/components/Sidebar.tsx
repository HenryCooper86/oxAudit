import {
  Bot,
  Boxes,
  Bug,
  FileSearch,
  LayoutDashboard,
  Settings,
  X,
} from "lucide-react";
import type { JSX } from "react";
import { SectionLabel } from "./ui";
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

/**
 * Primary navigation, following y-agent's NavSidebar: a Finder/Notes-style
 * rail on `--surface-secondary` with 10px uppercase section headers, 13px
 * items on the 4px control radius, and a pinned footer for Settings.
 */
export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }): JSX.Element {
  const page = useAppStore((state) => state.page);
  const setPage = useAppStore((state) => state.setPage);

  const selectPage = (nextPage: Page) => {
    setPage(nextPage);
    onClose();
  };

  const navigationButton = ({ page: itemPage, label, icon: Icon }: NavigationItem) => {
    const active = page === itemPage;
    return (
      <button
        key={itemPage}
        type="button"
        aria-current={active ? "page" : undefined}
        onClick={() => selectPage(itemPage)}
        className={`mb-0.5 flex w-full items-center gap-2 rounded-sm border px-2.5 py-[7px] text-left text-[13px] leading-tight font-medium transition-colors duration-150 ${ active ? "border-border bg-surface-active text-text-primary" : "border-transparent text-text-primary hover:bg-accent-subtle" }`}
      >
        <span
          className={`inline-flex h-[18px] w-[18px] shrink-0 items-center justify-center ${ active ? "text-accent" : "text-text-muted" }`}
        >
          <Icon aria-hidden="true" size={15} />
        </span>
        <span className="min-w-0 flex-1 truncate">{label}</span>
      </button>
    );
  };

  return (
    <>
      {open && (
        <button
          type="button"
          aria-label="Close navigation"
          tabIndex={-1}
          onClick={onClose}
          className="fixed inset-0 z-30 bg-black/60 min-[900px]:hidden"
        />
      )}
      <aside
        aria-label="Primary navigation"
        className={`z-40 flex h-full w-60 flex-col border-r border-border bg-surface-secondary transition-transform max-[900px]:fixed max-[900px]:inset-y-0 max-[900px]:left-0 ${ open ? "max-[900px]:visible max-[900px]:translate-x-0" : "max-[900px]:invisible max-[900px]:-translate-x-full" }`}
      >
        <div className="flex items-center justify-end px-2 pt-1.5 min-[900px]:hidden">
          <button
            type="button"
            aria-label="Close navigation"
            onClick={onClose}
            className="rounded-sm p-1.5 text-text-muted transition-colors hover:bg-surface-hover hover:text-text-primary"
          >
            <X aria-hidden="true" size={16} />
          </button>
        </div>

        <nav className="flex min-h-0 flex-1 flex-col overflow-y-auto px-2 pt-1.5">
          {NAVIGATION_GROUPS.map((group) => (
            <div key={group.label}>
              <div className="px-2.5 pt-2.5 pb-1">
                <SectionLabel>{group.label}</SectionLabel>
              </div>
              {group.items.map(navigationButton)}
            </div>
          ))}
        </nav>

        <div className="shrink-0 border-t border-border px-2 py-1.5">
          {navigationButton({ page: "settings", label: "Settings", icon: Settings })}
        </div>
      </aside>
    </>
  );
}
