import { Menu, Monitor, Moon, Sun } from "lucide-react";
import { useCallback, type JSX } from "react";
import { savePersistedThemePreference } from "../../lib/settingsRequests";
import { useAppStore } from "../../lib/stores";
import { normalizeThemePreference, type ThemePreference } from "../../lib/theme";
import { PAGE_META } from "../../lib/workbench";
import { BrandMark } from "../brand/BrandMark";

const NEXT_PREFERENCE: Record<ThemePreference, ThemePreference> = {
  dark: "light",
  light: "system",
  system: "dark",
};

const PREFERENCE_ICON = { dark: Moon, light: Sun, system: Monitor } as const;
const PREFERENCE_LABEL = {
  dark: "Dark theme",
  light: "Light theme",
  system: "System theme",
} as const;

function ThemeToggle(): JSX.Element | null {
  const settings = useAppStore((state) => state.settings);
  const setSettings = useAppStore((state) => state.setSettings);

  const preference = normalizeThemePreference(settings?.theme);
  const Icon = PREFERENCE_ICON[preference];
  const next = NEXT_PREFERENCE[preference];

  const cycle = useCallback(() => {
    void savePersistedThemePreference(
      () => useAppStore.getState().settings,
      next,
      setSettings,
    ).catch(() => {
      /* the settings page surfaces write failures; the header stays quiet */
    });
  }, [next, setSettings]);

  if (!settings) return null;

  return (
    <button
      type="button"
      onClick={cycle}
      title={`${PREFERENCE_LABEL[preference]} — switch to ${PREFERENCE_LABEL[next].toLowerCase()}`}
      aria-label={`${PREFERENCE_LABEL[preference]}. Switch to ${PREFERENCE_LABEL[next].toLowerCase()}`}
      className="flex h-8 w-8 items-center justify-center rounded-sm border border-transparent text-text-muted transition-colors duration-150 hover:border-border hover:bg-surface-hover hover:text-text-primary"
    >
      <Icon aria-hidden="true" size={15} />
    </button>
  );
}

export function WorkbenchHeader({
  onOpenNavigation,
}: {
  onOpenNavigation: () => void;
}): JSX.Element {
  const page = useAppStore((state) => state.page);
  const meta = PAGE_META[page];

  return (
    <header className="flex h-[52px] items-center gap-3 border-b border-border bg-surface-primary px-4">
      <button
        id="navigation-menu-button"
        type="button"
        aria-label="Open navigation"
        onClick={onOpenNavigation}
        className="hidden rounded-sm p-1.5 text-text-secondary transition-colors hover:bg-surface-hover hover:text-text-primary max-[900px]:inline-flex"
      >
        <Menu aria-hidden="true" size={17} />
      </button>

      <h1
        aria-label="oxAudit"
        className="flex shrink-0 items-center gap-1.5 pr-0.5 font-display text-[17px] font-medium tracking-[-0.02em] text-text-primary"
      >
        <BrandMark className="h-[18px] w-[18px] text-accent" />
        <span aria-hidden="true">Audit</span>
      </h1>

      <div className="min-w-0 truncate text-[13px]">
        <span className="text-text-muted">{meta.group}</span>
        <span aria-hidden="true" className="px-2 text-text-muted opacity-60">
          /
        </span>
        <span className="font-medium text-text-secondary">{meta.title}</span>
      </div>

      <div className="ml-auto flex shrink-0 items-center gap-1">
        <ThemeToggle />
      </div>
    </header>
  );
}
