/**
 * Theme resolution — pure logic, no React and no DOM globals, so it can be
 * unit-tested directly. The React binding lives in `useTheme.ts`.
 *
 * Modeled on y-agent's `y-gui/src/hooks/useTheme.ts`: a stored *preference*
 * ("dark" | "light" | "system") resolves against the OS colour scheme into an
 * *effective* theme, which is written to `document.documentElement`'s
 * `data-theme` attribute. Every design token in `index.css` keys off that
 * attribute.
 */

export type ThemePreference = "dark" | "light" | "system";
export type ResolvedTheme = "dark" | "light";

export const THEME_PREFERENCES: readonly ThemePreference[] = ["dark", "light", "system"];

/** Persisted separately from settings so the first paint never flashes. */
export const THEME_CACHE_KEY = "vc.themePreference";

const DEFAULT_PREFERENCE: ThemePreference = "dark";

/** Settings arrive from Rust as a bare `String`; anything unrecognized is dark. */
export function normalizeThemePreference(value: unknown): ThemePreference {
  return typeof value === "string" &&
    (THEME_PREFERENCES as readonly string[]).includes(value)
    ? (value as ThemePreference)
    : DEFAULT_PREFERENCE;
}

export function resolveTheme(
  preference: ThemePreference,
  systemPrefersDark: boolean,
): ResolvedTheme {
  if (preference === "system") return systemPrefersDark ? "dark" : "light";
  return preference;
}

/** Minimal structural type so tests can pass a fake in place of MediaQueryList. */
export interface SystemThemeQuery {
  matches: boolean;
  addEventListener?: (type: "change", listener: (event: { matches: boolean }) => void) => void;
  removeEventListener?: (type: "change", listener: (event: { matches: boolean }) => void) => void;
  addListener?: (listener: (event: { matches: boolean }) => void) => void;
  removeListener?: (listener: (event: { matches: boolean }) => void) => void;
}

/**
 * Subscribe to OS colour-scheme changes. Handles both the modern
 * `addEventListener` API and the deprecated `addListener` fallback, and is a
 * no-op when `matchMedia` is unavailable.
 */
export function subscribeToSystemTheme(
  query: SystemThemeQuery | null | undefined,
  onChange: (prefersDark: boolean) => void,
): () => void {
  if (!query) return () => {};

  const handler = (event: { matches: boolean }) => onChange(event.matches);

  if (query.addEventListener && query.removeEventListener) {
    query.addEventListener("change", handler);
    return () => query.removeEventListener?.("change", handler);
  }

  if (query.addListener && query.removeListener) {
    query.addListener(handler);
    return () => query.removeListener?.(handler);
  }

  return () => {};
}

export function systemPrefersDark(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return true;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function systemThemeQuery(): SystemThemeQuery | undefined {
  if (typeof window === "undefined" || !window.matchMedia) return undefined;
  return window.matchMedia("(prefers-color-scheme: dark)");
}

export function applyResolvedTheme(theme: ResolvedTheme): void {
  if (typeof document === "undefined") return;
  document.documentElement.setAttribute("data-theme", theme);
}

export function readCachedThemePreference(): ThemePreference {
  if (typeof localStorage === "undefined") return DEFAULT_PREFERENCE;
  try {
    return normalizeThemePreference(localStorage.getItem(THEME_CACHE_KEY));
  } catch {
    return DEFAULT_PREFERENCE;
  }
}

export function cacheThemePreference(preference: ThemePreference): void {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(THEME_CACHE_KEY, preference);
  } catch {
    /* private mode / quota — the settings file remains the source of truth */
  }
}
