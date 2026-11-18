/**
 * The Assistant's two side panels, Conversations and Activity.
 *
 * They dock on the right of the conversation the way oxFuzz docks its
 * observation panels: at most one is open, both are closed by default, and the
 * open one is remembered. Below `ASSISTANT_DRAWER_QUERY` the panel overlays
 * the conversation as a drawer instead of squeezing it.
 */
export type AssistantPanel = "sessions" | "activity";

export const ASSISTANT_PANEL_STORAGE_KEY = "oxaudit.panel.assistant.v1";

/** Narrower than this, a docked 320px panel would leave the conversation too little room. */
export const ASSISTANT_DRAWER_QUERY = "(max-width: 1099px)";

function browserStorage(): Storage | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}

export function readAssistantPanel(
  storage: Pick<Storage, "getItem"> | null = browserStorage(),
): AssistantPanel | null {
  try {
    const value = storage?.getItem(ASSISTANT_PANEL_STORAGE_KEY);
    return value === "sessions" || value === "activity" ? value : null;
  } catch {
    return null;
  }
}

export function saveAssistantPanel(
  panel: AssistantPanel | null,
  storage: Pick<Storage, "setItem"> | null = browserStorage(),
): void {
  try {
    storage?.setItem(ASSISTANT_PANEL_STORAGE_KEY, panel ?? "none");
  } catch {
    /* private mode or quota: the panel still opens for this visit */
  }
}

/** Pressing a panel's toggle opens it in place of the other, or closes it if it is open. */
export function toggleAssistantPanel(
  current: AssistantPanel | null,
  requested: AssistantPanel,
): AssistantPanel | null {
  return current === requested ? null : requested;
}
