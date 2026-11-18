import { CheckCircle2, Loader2, Menu, Monitor, Moon, PanelLeft, Sun, XCircle } from "lucide-react";
import { useCallback, useMemo, type JSX } from "react";
import { selectHeaderActions, useHeaderActionStore } from "../../lib/headerActions";
import { savePersistedThemePreference } from "../../lib/settingsRequests";
import { useAppStore } from "../../lib/stores";
import { normalizeThemePreference, type ThemePreference } from "../../lib/theme";
import { settingsSection } from "../../lib/settingsSections";
import { PAGE_META, SHELL_HEADING_PAGES } from "../../lib/workbench";
import { Button } from "../ui";
import { HeaderToggle } from "./HeaderToggle";
import { PAGE_ICONS } from "./pageIcons";

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
    <HeaderToggle
      label={`${PREFERENCE_LABEL[preference]}. Switch to ${PREFERENCE_LABEL[next].toLowerCase()}`}
      onClick={cycle}
    >
      <Icon aria-hidden="true" size={16} />
    </HeaderToggle>
  );
}

/** Page toggles registered through `useHeaderActions`, left of the theme button. */
function PageActions(): JSX.Element | null {
  const owners = useHeaderActionStore((state) => state.owners);
  const actions = useMemo(() => selectHeaderActions({ owners }), [owners]);
  if (actions.length === 0) return null;
  return (
    <div data-header-actions className="flex items-center gap-1">
      {actions.map((action) => {
        const { id, label, icon: Icon, pressed, controls, keyShortcuts, disabled, onSelect } = action;
        if (action.kind === "status") {
          const tone = action.tone ?? "muted";
          const colour = { success: "text-success", error: "text-error", warning: "text-warning", muted: "text-text-muted" }[tone];
          return (
            <span
              key={id}
              role={tone === "error" ? "alert" : "status"}
              className={`mr-1 inline-flex min-w-0 max-w-56 items-center gap-1.5 text-[12px] max-[700px]:hidden ${colour}`}
            >
              {tone === "success" && <CheckCircle2 size={13} aria-hidden="true" className="shrink-0" />}
              {tone === "error" && <XCircle size={13} aria-hidden="true" className="shrink-0" />}
              <span className="truncate">{action.text ?? label}</span>
            </span>
          );
        }
        if (action.kind === "button") {
          return (
            <Button
              key={id}
              variant={action.variant ?? "outline"}
              size="sm"
              disabled={disabled || action.busy}
              aria-keyshortcuts={keyShortcuts}
              onClick={onSelect}
            >
              {action.busy ? (
                <Loader2 size={13} aria-hidden="true" className="animate-spin" />
              ) : (
                <Icon size={13} aria-hidden="true" />
              )}
              {action.text ?? label}
            </Button>
          );
        }
        return (
          <HeaderToggle
            key={id}
            label={label}
            pressed={pressed}
            controls={controls}
            keyShortcuts={keyShortcuts}
            disabled={disabled}
            onClick={onSelect}
          >
            <Icon aria-hidden="true" size={16} />
          </HeaderToggle>
        );
      })}
    </div>
  );
}

/**
 * The shell header, after oxFuzz: sidebar toggle, the current page's icon and
 * title on the left; page toggles and the theme button on the right. It is the
 * window's drag region when the macOS title bar overlays the webview.
 */
export function WorkbenchHeader({
  onOpenNavigation,
  navigationHidden,
  onToggleNavigation,
  reserveTrafficLights = false,
}: {
  onOpenNavigation: () => void;
  navigationHidden: boolean;
  onToggleNavigation: () => void;
  /** macOS desktop with the sidebar hidden: keep the title clear of the traffic lights. */
  reserveTrafficLights?: boolean;
}): JSX.Element {
  const page = useAppStore((state) => state.page);
  const section = useAppStore((state) => state.settingsSection);
  const inSettings = page === "settings";
  const meta = PAGE_META[page];
  const PageIcon = PAGE_ICONS[page];
  const Title = inSettings || SHELL_HEADING_PAGES.has(page) ? "h1" : "span";

  return (
    <header
      data-tauri-drag-region
      className={`flex h-[52px] min-w-0 select-none items-center justify-between gap-3 border-b border-border bg-surface-primary pr-4 min-[900px]:pr-6 ${reserveTrafficLights ? "pl-[78px]" : "pl-4 min-[900px]:pl-6"}`}
    >
      <div className="flex min-w-0 items-center gap-3" data-tauri-drag-region>
        <span className="hidden max-[900px]:inline-flex">
          <HeaderToggle id="navigation-menu-button" label="Open navigation" onClick={onOpenNavigation}>
            <Menu aria-hidden="true" size={18} />
          </HeaderToggle>
        </span>
        <span className="inline-flex max-[900px]:hidden">
          <HeaderToggle
            label={navigationHidden ? "Expand navigation" : "Collapse navigation"}
            expanded={!navigationHidden}
            controls="primary-navigation"
            onClick={onToggleNavigation}
          >
            <PanelLeft aria-hidden="true" size={18} />
          </HeaderToggle>
        </span>
        {inSettings ? (
          /* oxFuzz's settings header: the section title, italic display, 17px. */
          <Title
            data-tauri-drag-region
            className="min-w-0 truncate font-display text-[17px] font-normal italic tracking-[0.01em] text-text-primary"
          >
            {settingsSection(section).title}
          </Title>
        ) : (
          <>
            <span data-tauri-drag-region className="inline-flex shrink-0 text-text-secondary">
              <PageIcon aria-hidden="true" size={18} strokeWidth={1.75} />
            </span>
            <Title
              data-tauri-drag-region
              className="min-w-0 truncate font-display text-[14px] font-medium text-text-secondary"
            >
              {meta.title}
            </Title>
          </>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-1">
        <PageActions />
        <ThemeToggle />
      </div>
    </header>
  );
}
