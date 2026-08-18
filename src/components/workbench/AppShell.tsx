import { useCallback, useEffect, useState, type JSX } from "react";
import { Sidebar } from "../Sidebar";
import { StatusBar } from "./StatusBar";
import { WorkbenchHeader } from "./WorkbenchHeader";

export function AppShell({ children }: { children: React.ReactNode }): JSX.Element {
  const [navigationOpen, setNavigationOpen] = useState(false);

  const closeNavigation = useCallback(() => {
    setNavigationOpen(false);
    requestAnimationFrame(() => {
      document.getElementById("navigation-menu-button")?.focus();
    });
  }, []);

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
    <div className="grid h-full grid-cols-[208px_minmax(0,1fr)] overflow-hidden bg-ink-950 max-[900px]:grid-cols-1">
      <Sidebar open={navigationOpen} onClose={closeNavigation} />
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
