import type { Page } from "./workbench";

/**
 * Composer slash commands.
 *
 * Kept as pure data + a matcher so the behaviour that decides *which* command a
 * keystroke runs is testable without a DOM. Each command maps onto an action
 * that already exists in the assistant or shell, so a slash command is a
 * shortcut, never a second implementation of something.
 */

export type SlashAction =
  | { kind: "navigate"; page: Page }
  | { kind: "resume" }
  | { kind: "clear" }
  | { kind: "copy" };

export interface SlashCommand {
  /** What the user types, e.g. `/scan`. */
  id: string;
  /** The command name after the slash; this is what matching runs against. */
  name: string;
  description: string;
  action: SlashAction;
}

export const SLASH_COMMANDS: SlashCommand[] = [
  {
    id: "/scan",
    name: "scan",
    description: "Open the Source Scan workbench",
    action: { kind: "navigate", page: "source-scan" },
  },
  {
    id: "/cve",
    name: "cve",
    description: "Open CVE Research",
    action: { kind: "navigate", page: "cve-research" },
  },
  {
    id: "/resume",
    name: "resume",
    description: "Switch to your most recent other conversation",
    action: { kind: "resume" },
  },
  {
    id: "/clear",
    name: "clear",
    description: "Clear the current conversation",
    action: { kind: "clear" },
  },
  {
    id: "/copy",
    name: "copy",
    description: "Copy the last assistant reply",
    action: { kind: "copy" },
  },
];

/**
 * The query after a leading slash, or `null` when `input` is not a slash
 * command. Leading whitespace is ignored, so "  /scan" still counts.
 */
export function slashQuery(input: string): string | null {
  const trimmed = input.replace(/^\s+/, "");
  if (!trimmed.startsWith("/")) return null;
  return trimmed.slice(1);
}

/**
 * Commands matching the current input, in definition order.
 *
 * A bare `/` lists every command; otherwise matching is a plain prefix match on
 * the command name — exactly how a slash menu behaves, and deliberately not the
 * palette's free-text keyword ranking (a command menu should be predictable).
 */
export function matchingSlashCommands(input: string): SlashCommand[] {
  const query = slashQuery(input);
  if (query === null) return [];
  const needle = query.trim().toLowerCase();
  if (!needle) return SLASH_COMMANDS;
  return SLASH_COMMANDS.filter((command) => command.name.startsWith(needle));
}
