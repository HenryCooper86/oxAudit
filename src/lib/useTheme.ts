import { useEffect, useState } from "react";
import {
  applyResolvedTheme,
  cacheThemePreference,
  normalizeThemePreference,
  readCachedThemePreference,
  resolveTheme,
  subscribeToSystemTheme,
  systemPrefersDark,
  systemThemeQuery,
  type ResolvedTheme,
} from "./theme";
import { useAppStore } from "./stores";

/**
 * Applies the effective theme to `<html data-theme>`.
 *
 * The preference comes from settings once they load; until then it comes from
 * the localStorage cache, so a light-theme user does not get a dark flash on
 * launch. Call once, from the app shell.
 */
export function useAppTheme(): ResolvedTheme {
  const settings = useAppStore((state) => state.settings);
  const preference = settings
    ? normalizeThemePreference(settings.theme)
    : readCachedThemePreference();

  const [prefersDark, setPrefersDark] = useState(systemPrefersDark);

  useEffect(() => subscribeToSystemTheme(systemThemeQuery(), setPrefersDark), []);

  const resolved = resolveTheme(preference, prefersDark);

  useEffect(() => {
    applyResolvedTheme(resolved);
  }, [resolved]);

  useEffect(() => {
    if (settings) cacheThemePreference(preference);
  }, [preference, settings]);

  return resolved;
}
