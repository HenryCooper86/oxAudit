import { useCallback, useEffect, useState, type JSX } from "react";
import {
  cacheNavigationCollapsed,
  readNavigationCollapsed,
  resolveNavigationCollapsed,
} from "../../lib/navigationPreference";
import { useAppStore } from "../../lib/stores";
import { useAppTheme } from "../../lib/useTheme";
import { Sidebar } from "../Sidebar";
import { StatusBar } from "./StatusBar";
import { WorkbenchHeader } from "./WorkbenchHeader";

export function AppShell({ children }: { children: React.ReactNode }): JSX.Element {
  const [navigationOpen, setNavigationOpen] = useState(false);
  const page = useAppStore((state) => state.page);
  const [collapsedPreference, setCollapsedPreference] = useState<boolean | null>(
    readNavigationCollapsed,
  );
  const compactNavigation = resolveNavigationCollapsed(
    collapsedPreference,
    page === "assistant",
  );

  useAppTheme();

  const closeNavigation = useCallback(() => {
    setNavigationOpen(false);
    requestAnimationFrame(() => {
      document.getElementById("navigation-menu-button")?.focus();
    });
  }, []);

  const toggleCompactNavigation = useCallback(() => {
    const next = !compactNavigation;
    setCollapsedPreference(next);
    cacheNavigationCollapsed(next);
  }, [compactNavigation]);

  useEffect(() => {
    if (!navigationOpen) return;

    requestAnimationFrame(() => {
      document
        .querySelector<HTMLElement>('[aria-label="Primary navigation"] button')
        ?.focus();
    });

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeNavigation();
        return;
      }

      if (event.key !== "Tab") return;

      const navigation = document.querySelector<HTMLElement>(
        '[aria-label="Primary navigation"]',
      );
      const focusable = Array.from(
        navigation?.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ) ?? [],
      ).filter((element) => element.getClientRects().length > 0);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];

      if (!first || !last) return;

      if (
        event.shiftKey &&
        (document.activeElement === first || !navigation?.contains(document.activeElement))
      ) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [closeNavigation, navigationOpen]);

  return (
    <div
      className={`grid h-full overflow-hidden bg-surface-primary transition-[grid-template-columns] duration-200 motion-reduce:transition-none max-[900px]:grid-cols-1 ${compactNavigation ? "grid-cols-[52px_minmax(0,1fr)]" : "grid-cols-[240px_minmax(0,1fr)]"}`}
    >
      <Sidebar
        open={navigationOpen}
        onClose={closeNavigation}
        compact={compactNavigation}
        onToggleCompact={toggleCompactNavigation}
      />
      <section
        inert={navigationOpen}
        className="grid min-w-0 grid-rows-[52px_minmax(0,1fr)_28px] overflow-hidden"
      >
        <WorkbenchHeader onOpenNavigation={() => setNavigationOpen(true)} />
        <main id="main-content" className="min-h-0 overflow-y-auto">
          {children}
        </main>
        <StatusBar />
      </section>
    </div>
  );
}
