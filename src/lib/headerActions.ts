import { useEffect } from "react";
import type { LucideIcon } from "lucide-react";
import { create } from "zustand";

/**
 * Page-specific toggles in the shell header, oxFuzz's `HeaderToggle` row.
 *
 * The header renders a page's actions to the left of the theme button. A page
 * registers them with `useHeaderActions(owner, actions)`; they disappear when
 * the page unmounts, so navigating away never leaves another page's toggles
 * behind. Actions are icon buttons: 32px, 8px radius, accent on accent-subtle
 * while `pressed`.
 */
export interface HeaderAction {
  /** Stable within its owner; the React key. */
  id: string;
  /** Accessible name and tooltip. Name the thing it shows ("Activity panel"). */
  label: string;
  icon: LucideIcon;
  /** Present for a toggle (rendered with `aria-pressed`); omit for a one-shot action. */
  pressed?: boolean;
  /** The id of the region the toggle shows or hides. */
  controls?: string;
  /** `aria-keyshortcuts` value, e.g. "Meta+F Control+F". */
  keyShortcuts?: string;
  disabled?: boolean;
  onSelect: () => void;
  /**
   * Optional kind. Omitted: an icon toggle or action. `"button"`: a labelled
   * 28px button showing `text` (Settings' Reset and Save). `"status"`: a
   * short live-region message showing `text`, not interactive.
   */
  kind?: "button" | "status";
  /** The visible text of a `"button"` or `"status"` action. */
  text?: string;
  /** `"button"` styling; the one primary action per view is `"primary"`. */
  variant?: "primary" | "outline";
  /** `"button"`: show a spinner and ignore presses. */
  busy?: boolean;
  /** `"status"` colour; an `"error"` status is announced as an alert. */
  tone?: "success" | "error" | "warning" | "muted";
}

interface HeaderActionStore {
  /** Registered actions by owner, in registration order. */
  owners: ReadonlyArray<{ owner: string; actions: readonly HeaderAction[] }>;
  setActions: (owner: string, actions: readonly HeaderAction[]) => void;
  clearActions: (owner: string) => void;
}

export const useHeaderActionStore = create<HeaderActionStore>((set) => ({
  owners: [],
  setActions: (owner, actions) =>
    set((state) => {
      const index = state.owners.findIndex((entry) => entry.owner === owner);
      if (index === -1) return { owners: [...state.owners, { owner, actions }] };
      const owners = state.owners.slice();
      owners[index] = { owner, actions };
      return { owners };
    }),
  clearActions: (owner) =>
    set((state) => ({ owners: state.owners.filter((entry) => entry.owner !== owner) })),
}));

/** Every registered header action, flattened in owner order. */
export function selectHeaderActions(state: Pick<HeaderActionStore, "owners">): HeaderAction[] {
  return state.owners.flatMap((entry) => entry.actions);
}

/**
 * Show `actions` in the shell header while the calling component is mounted.
 *
 * `owner` identifies the caller (use the page id). Pass a memoized array:
 * every new array identity re-publishes, which is cheap but re-renders the
 * header.
 */
export function useHeaderActions(owner: string, actions: readonly HeaderAction[]): void {
  const setActions = useHeaderActionStore((state) => state.setActions);
  const clearActions = useHeaderActionStore((state) => state.clearActions);
  useEffect(() => {
    setActions(owner, actions);
  }, [owner, actions, setActions]);
  useEffect(() => () => clearActions(owner), [owner, clearActions]);
}
