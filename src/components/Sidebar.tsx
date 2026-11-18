import { ArrowLeft, FolderOpen, Plus, X } from "lucide-react";
import { useEffect, useState, type JSX } from "react";
import { version } from "../../package.json";
import { activateRecentProject, openProjectFromShell } from "../features/project-home/openProject";
import { useScanWorkStore } from "../features/project-home/coordinator";
import { api } from "../lib/api";
import { detectPlatform } from "../lib/platform";
import { useAppStore } from "../lib/stores";
import type { RecentProject } from "../lib/types";
import { SETTINGS_SECTIONS } from "../lib/settingsSections";
import { NAVIGATION_SECTIONS, PAGE_META, type Page } from "../lib/workbench";
import { BrandMark } from "./brand/BrandMark";
import { SectionLabel } from "./ui";
import { PAGE_ICONS } from "./workbench/pageIcons";

/** Recent projects shown in the sidebar; the command palette lists more. */
export const SIDEBAR_RECENT_LIMIT = 5;

/** oxFuzz's nav item: 13px/500 label, 18px icon, 8px radius. */
const ITEM_BASE =
  "mb-0.5 flex w-full items-center gap-2 rounded-md border px-2.5 py-[7px] text-left text-[13px] font-medium leading-tight transition-colors duration-150";
const ITEM_ACTIVE = "border-border bg-surface-active text-text-primary";
const ITEM_IDLE = "border-transparent text-text-secondary hover:bg-accent-subtle hover:text-text-primary";

type RecentState =
  | { status: "loading" }
  | { status: "ready"; projects: RecentProject[] }
  | { status: "error" };

/**
 * Primary navigation, following oxFuzz's sidebar: [macOS title-bar spacer],
 * brand, "Open project", recent projects, the grouped tools, then a footer
 * with Settings, the command-palette hint and the version. The middle region
 * scrolls as one; the footer stays pinned above it with a hairline divider,
 * so nothing is hidden behind it.
 */
export function Sidebar({
  open,
  onClose,
  hidden = false,
  onOpenCommands,
}: {
  /** Drawer state below 900px. */
  open: boolean;
  onClose: () => void;
  /** Hidden at >= 900px (the header toggle). */
  hidden?: boolean;
  onOpenCommands: () => void;
}): JSX.Element {
  const page = useAppStore((state) => state.page);
  const setPage = useAppStore((state) => state.setPage);
  const settingsSection = useAppStore((state) => state.settingsSection);
  const setSettingsSection = useAppStore((state) => state.setSettingsSection);
  const closeSettings = useAppStore((state) => state.closeSettings);
  const inSettings = page === "settings";
  const activeProject = useAppStore((state) => state.activeProject);
  const selectedProject = useAppStore((state) => state.selectedProject);
  const scanRunning = useScanWorkStore((state) => Boolean(state.active));
  const [recent, setRecent] = useState<RecentState>({ status: "loading" });
  const shortcut = detectPlatform() === "macos" ? "⌘K" : "Ctrl K";

  // The same source as the command palette. Reloaded when the project changes
  // or a scan finishes, since either can add or reorder recent projects.
  useEffect(() => {
    let current = true;
    void api
      .listSourceProjects(SIDEBAR_RECENT_LIMIT)
      .then((projects) => {
        if (current) setRecent({ status: "ready", projects: projects.slice(0, SIDEBAR_RECENT_LIMIT) });
      })
      .catch(() => {
        if (current) setRecent({ status: "error" });
      });
    return () => {
      current = false;
    };
  }, [activeProject, selectedProject, scanRunning]);

  const selectPage = (nextPage: Page) => {
    setPage(nextPage);
    onClose();
  };

  const navigationButton = (itemPage: Page) => {
    const active = page === itemPage;
    const Icon = PAGE_ICONS[itemPage];
    return (
      <button
        key={itemPage}
        type="button"
        aria-current={active ? "page" : undefined}
        onClick={() => selectPage(itemPage)}
        className={`${ITEM_BASE} ${active ? ITEM_ACTIVE : ITEM_IDLE}`}
      >
        <Icon aria-hidden="true" size={18} strokeWidth={1.75} className={`shrink-0 ${active ? "text-accent" : ""}`} />
        <span className="min-w-0 flex-1 truncate">{PAGE_META[itemPage].title}</span>
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
          className="fixed inset-0 z-30 bg-black/40 backdrop-blur-[2px] min-[900px]:hidden"
        />
      )}
      <aside
        id="primary-navigation"
        aria-label="Primary navigation"
        className={`relative z-40 flex h-full min-h-0 w-60 select-none flex-col overflow-hidden border-r border-border bg-surface-secondary max-[900px]:fixed max-[900px]:inset-y-0 max-[900px]:left-0 max-[900px]:shadow-lg max-[900px]:transition-transform max-[900px]:duration-200 ${hidden ? "min-[900px]:hidden" : ""} ${open ? "max-[900px]:visible max-[900px]:translate-x-0" : "max-[900px]:invisible max-[900px]:-translate-x-full"}`}
      >
        {/* macOS desktop only: room for the traffic lights, and a drag handle. */}
        <div className="titlebar-spacer" data-tauri-drag-region />

        <div className="sidebar-brand flex shrink-0 items-center gap-2 px-3.5 pb-2.5 pt-3.5" data-tauri-drag-region>
          <BrandMark className="h-5 w-5 shrink-0 text-accent" />
          <span className="font-display text-[15px] font-bold tracking-[0.02em] text-text-primary" data-tauri-drag-region>
            oxAudit
          </span>
          <button
            type="button"
            aria-label="Close navigation"
            onClick={onClose}
            className="ml-auto inline-flex h-7 w-7 items-center justify-center rounded-md text-text-muted transition-colors hover:bg-surface-hover hover:text-text-primary min-[900px]:hidden"
          >
            <X aria-hidden="true" size={16} />
          </button>
        </div>

        <div
          data-sidebar-scroll
          className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-2 pb-3 pt-1.5"
        >
          {inSettings ? (
            <>
              <button
                type="button"
                onClick={() => {
                  closeSettings();
                  onClose();
                }}
                className={`${ITEM_BASE} ${ITEM_IDLE}`}
              >
                <ArrowLeft aria-hidden="true" size={16} strokeWidth={1.75} className="shrink-0" />
                <span>Back</span>
              </button>
              <nav id="primary-navigation-content" aria-label="Settings sections" className="mt-1.5">
                {SETTINGS_SECTIONS.map(({ id, title, icon: Icon }) => {
                  const active = settingsSection === id;
                  return (
                    <button
                      key={id}
                      type="button"
                      aria-current={active ? "true" : undefined}
                      onClick={() => {
                        setSettingsSection(id);
                        onClose();
                      }}
                      className={`${ITEM_BASE} ${active ? ITEM_ACTIVE : ITEM_IDLE}`}
                    >
                      <Icon aria-hidden="true" size={16} strokeWidth={1.75} className={`shrink-0 ${active ? "text-accent" : ""}`} />
                      <span className="min-w-0 flex-1 truncate">{title}</span>
                    </button>
                  );
                })}
              </nav>
            </>
          ) : (
            <>
          <button
            type="button"
            onClick={() => {
              onClose();
              void openProjectFromShell();
            }}
            className={`${ITEM_BASE} border-transparent font-semibold text-text-primary hover:bg-accent-subtle`}
          >
            <Plus aria-hidden="true" size={18} className="shrink-0 text-accent" />
            <span>Open project</span>
          </button>

          <div className="px-2.5 pb-1 pt-2.5">
            <SectionLabel>Recent</SectionLabel>
          </div>
          {recent.status === "ready" && recent.projects.length === 0 && (
            <p className="px-2.5 pb-1.5 text-[11px] leading-relaxed text-text-muted">
              No projects yet. Open a project folder to start auditing.
            </p>
          )}
          {recent.status === "error" && (
            <p className="px-2.5 pb-1.5 text-[11px] leading-relaxed text-text-muted">
              Recent projects unavailable. Search with {shortcut} or open a folder.
            </p>
          )}
          {recent.status === "ready" &&
            recent.projects.map((project) => {
              const active = project.canonicalPath === activeProject;
              return (
                <button
                  key={project.projectId}
                  type="button"
                  title={project.canonicalPath}
                  aria-current={active ? "true" : undefined}
                  onClick={() => {
                    activateRecentProject(project.canonicalPath);
                    onClose();
                  }}
                  className={`${ITEM_BASE} ${active ? ITEM_ACTIVE : ITEM_IDLE}`}
                >
                  <FolderOpen aria-hidden="true" size={16} strokeWidth={1.75} className={`shrink-0 ${active ? "text-accent" : ""}`} />
                  <span className="min-w-0 flex-1 truncate">{project.displayName}</span>
                </button>
              );
            })}

          <nav id="primary-navigation-content" aria-label="Tools">
            {NAVIGATION_SECTIONS.map((section) => (
              <div key={section.group}>
                <div className="px-2.5 pb-1 pt-2.5">
                  <SectionLabel>{section.group}</SectionLabel>
                </div>
                {section.pages.map(navigationButton)}
              </div>
            ))}
          </nav>
            </>
          )}
        </div>

        <div className="shrink-0 border-t border-border px-2 pb-2 pt-1.5">
          {!inSettings && navigationButton("settings")}
          <button
            type="button"
            aria-label="Search tools and projects"
            aria-haspopup="dialog"
            aria-keyshortcuts="Meta+K Control+K"
            title={`Search tools and projects (${shortcut})`}
            onClick={onOpenCommands}
            className="mt-1 flex w-full items-center justify-center gap-1 rounded-md px-2 py-1 text-[11px] text-text-muted transition-colors hover:bg-surface-hover hover:text-text-primary"
          >
            Press
            <kbd className="rounded-sm border border-border px-1 font-sans text-[10px]">{shortcut}</kbd>
            to search
          </button>
          <p className="pt-0.5 text-center text-[11px] text-text-muted">oxAudit v{version}</p>
        </div>
      </aside>
    </>
  );
}
