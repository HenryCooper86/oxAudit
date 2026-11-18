/**
 * Whether the sidebar is hidden at desktop widths (>= 900px).
 *
 * The shell follows oxFuzz: the sidebar is either shown at full width or
 * hidden, toggled from the header. There is no icon-only rail and no page
 * forces a width, so the preference is simply the user's last choice and the
 * default is shown. Below 900px the sidebar is a drawer and this preference
 * does not apply.
 *
 * The key is new (v1 of "hidden"): the earlier `oxaudit.navigationCollapsed.v1`
 * meant "icon rail", and reading it as "hidden" would open the app with no
 * visible navigation for anyone who once chose the rail. The legacy key is
 * ignored, so those users start with the sidebar shown.
 */
export const NAVIGATION_HIDDEN_CACHE_KEY = "oxaudit.navigationHidden.v1";
/** The retired icon-rail preference. Read by nothing; named so tests can prove that. */
export const LEGACY_NAVIGATION_COLLAPSED_CACHE_KEY = "oxaudit.navigationCollapsed.v1";

export function parseNavigationHidden(value: unknown): boolean | null {
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
}

export function readNavigationHidden(): boolean | null {
  try {
    if (typeof localStorage === "undefined") return null;
    return parseNavigationHidden(localStorage.getItem(NAVIGATION_HIDDEN_CACHE_KEY));
  } catch {
    return null;
  }
}

export function cacheNavigationHidden(hidden: boolean): void {
  try {
    if (typeof localStorage === "undefined") return;
    localStorage.setItem(NAVIGATION_HIDDEN_CACHE_KEY, String(hidden));
  } catch {
    /* private mode / quota — keep the in-memory choice for this session */
  }
}

/** Shown unless the user hid it; no page overrides the choice. */
export function resolveNavigationHidden(preference: boolean | null): boolean {
  return preference ?? false;
}
