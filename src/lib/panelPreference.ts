const PANEL_COLLAPSED_CACHE_PREFIX = "oxaudit.panel";

export function panelCollapsedCacheKey(panelId: string): string {
  return `${PANEL_COLLAPSED_CACHE_PREFIX}.${panelId}.collapsed.v1`;
}

export function parsePanelCollapsed(value: unknown): boolean | null {
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
}

export function readPanelCollapsed(
  panelId: string,
  fallback = false,
): boolean {
  try {
    if (typeof localStorage === "undefined") return fallback;
    return (
      parsePanelCollapsed(
        localStorage.getItem(panelCollapsedCacheKey(panelId)),
      ) ?? fallback
    );
  } catch {
    return fallback;
  }
}

export function cachePanelCollapsed(
  panelId: string,
  collapsed: boolean,
): void {
  try {
    if (typeof localStorage === "undefined") return;
    localStorage.setItem(
      panelCollapsedCacheKey(panelId),
      String(collapsed),
    );
  } catch {
    /* private mode / quota — keep the in-memory choice for this session */
  }
}
