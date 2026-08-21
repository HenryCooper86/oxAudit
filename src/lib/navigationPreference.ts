/** Persisted independently so the shell can restore its width before settings load. */
export const NAVIGATION_COLLAPSED_CACHE_KEY = "oxaudit.navigationCollapsed.v1";

export function parseNavigationCollapsed(value: unknown): boolean | null {
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
}

export function readNavigationCollapsed(): boolean | null {
  if (typeof localStorage === "undefined") return null;
  try {
    return parseNavigationCollapsed(
      localStorage.getItem(NAVIGATION_COLLAPSED_CACHE_KEY),
    );
  } catch {
    return null;
  }
}

export function cacheNavigationCollapsed(collapsed: boolean): void {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(
      NAVIGATION_COLLAPSED_CACHE_KEY,
      String(collapsed),
    );
  } catch {
    /* private mode / quota — keep the in-memory choice for this session */
  }
}

/** Assistant starts compact until the user records an explicit preference. */
export function resolveNavigationCollapsed(
  preference: boolean | null,
  assistantPage: boolean,
): boolean {
  return preference ?? assistantPage;
}
