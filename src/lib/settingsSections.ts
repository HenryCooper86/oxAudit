import {
  Binary,
  Bot,
  Database,
  Info,
  LifeBuoy,
  Radar,
  SlidersHorizontal,
  Settings2,
  type LucideIcon,
} from "lucide-react";

export type SettingsSectionId =
  | "general"
  | "ai"
  | "scan-defaults"
  | "live-scanning"
  | "data-sources"
  | "binary-scanner"
  | "diagnostics"
  | "about";

export interface SettingsSection {
  id: SettingsSectionId;
  /** The sub-navigation label and the shell header title. */
  title: string;
  icon: LucideIcon;
}

/** The Settings sub-navigation, top to bottom (oxFuzz's `SETTINGS_SECTIONS`). */
export const SETTINGS_SECTIONS: readonly SettingsSection[] = [
  { id: "general", title: "General", icon: Settings2 },
  { id: "ai", title: "AI", icon: Bot },
  { id: "scan-defaults", title: "Scan defaults", icon: SlidersHorizontal },
  { id: "live-scanning", title: "Live scanning", icon: Radar },
  { id: "data-sources", title: "Data sources", icon: Database },
  { id: "binary-scanner", title: "Binary scanner", icon: Binary },
  { id: "diagnostics", title: "Diagnostics", icon: LifeBuoy },
  { id: "about", title: "About", icon: Info },
];

export const DEFAULT_SETTINGS_SECTION: SettingsSectionId = "general";

export function settingsSection(id: SettingsSectionId): SettingsSection {
  return SETTINGS_SECTIONS.find((section) => section.id === id) ?? SETTINGS_SECTIONS[0];
}
