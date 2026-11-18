/**
 * The Assistant composer's pure rules, after oxFuzz's `views/chatHelpers.ts`:
 * the Auto / "Plan & act" mode and the textarea's auto-grow sizing.
 */

/** Instruction prepended in Plan mode (no backend change: pure prompt steering). */
export const PLAN_PREFIX =
  "[Plan mode] Before taking any action or calling tools, lay out a concise, " +
  "numbered step-by-step plan for how you will approach this. Then proceed.";

/** Composer mode. `plan` prepends a planning instruction to the message sent to the model. */
export type ChatMode = "auto" | "plan";

/**
 * Build the message actually sent to the model for a given mode.
 *
 * Only the model's copy changes: the transcript, the session file, rewind and
 * search all keep the text the person typed.
 */
export function applyMode(text: string, mode: ChatMode): string {
  return mode === "plan" ? `${PLAN_PREFIX}\n\n${text}` : text;
}

export const CHAT_MODE_STORAGE_KEY = "oxaudit.assistant.mode.v1";

type ReadableStorage = Pick<Storage, "getItem">;
type WritableStorage = Pick<Storage, "setItem">;

function browserStorage(): Storage | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}

/** The remembered composer mode; anything unrecognised is Auto. */
export function readChatMode(storage: ReadableStorage | null = browserStorage()): ChatMode {
  try {
    return storage?.getItem(CHAT_MODE_STORAGE_KEY) === "plan" ? "plan" : "auto";
  } catch {
    return "auto";
  }
}

export function saveChatMode(mode: ChatMode, storage: WritableStorage | null = browserStorage()): void {
  try {
    storage?.setItem(CHAT_MODE_STORAGE_KEY, mode);
  } catch {
    /* private mode or quota: the choice still holds for this visit */
  }
}

const COMPOSER_MIN_PX = 76;
const COMPOSER_EXPANDED_MIN_PX = 200;
const COMPOSER_MAX_FRACTION = 0.4;
const COMPOSER_EXPANDED_MAX_FRACTION = 0.5;

/**
 * Height of the composer textarea: about three lines at rest, growing with its
 * content up to a share of the window, then scrolling internally. Expanded
 * raises both the floor and the ceiling.
 */
export function composerLayout(input: {
  scrollHeight: number;
  expanded: boolean;
  viewportHeight: number;
}): { height: number; scroll: boolean } {
  const min = input.expanded ? COMPOSER_EXPANDED_MIN_PX : COMPOSER_MIN_PX;
  const fraction = input.expanded ? COMPOSER_EXPANDED_MAX_FRACTION : COMPOSER_MAX_FRACTION;
  const max = Math.max(min, Math.floor(input.viewportHeight * fraction));
  return {
    height: Math.min(Math.max(input.scrollHeight, min), max),
    scroll: input.scrollHeight > max,
  };
}

/** The label and body of a message saved by "Attach context", or null for an ordinary message. */
export function parseAttachedContext(content: string): { label: string; body: string } | null {
  // `.` stops at the first newline, so a label containing "]" still parses.
  const match = /^\[User-attached source context: (.*)\]\n\n/.exec(content);
  if (!match) return null;
  return { label: match[1], body: content.slice(match[0].length) };
}
