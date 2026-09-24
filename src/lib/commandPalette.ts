import { PAGE_META, type Page } from "./workbench";

/**
 * Matching and ranking for the command palette.
 *
 * Kept separate from the component so the behaviour that decides *which*
 * command someone gets when they type three characters and press Enter is
 * testable without a DOM. That is the part which, when wrong, quietly runs the
 * wrong thing.
 */

export interface Command {
  id: string;
  title: string;
  /** Where it appears in the grouped list. */
  group: string;
  /**
   * Extra words that should match this command without appearing in its title —
   * what someone might reasonably type when they do not know what a screen is
   * called here.
   */
  keywords?: string[];
  /** Shown right-aligned, e.g. a keyboard shortcut. */
  hint?: string;
}

export interface NavigateCommand extends Command {
  kind: "navigate";
  page: Page;
}

/**
 * Switch the active project.
 *
 * A consultant holds a dozen client codebases at once, and re-picking a folder
 * to move between them turns a two-second action into a file dialog. Projects
 * are commands for the same reason screens are.
 */
export interface ProjectCommand extends Command {
  kind: "project";
  projectPath: string;
}

export type PaletteCommand = NavigateCommand | ProjectCommand;

/**
 * Words people type when looking for a screen, beyond its title.
 *
 * These matter more than they look: someone arriving from another scanner
 * types "sarif" or "sbom", not "Export Center". A palette that only matches
 * its own vocabulary is a palette for people who already know the product.
 */
const KEYWORDS: Record<Page, string[]> = {
  dashboard: ["home", "overview", "start"],
  portfolio: ["projects", "rescan", "schedule", "cadence", "stale"],
  "source-scan": ["code", "secrets", "sast", "patterns", "grep"],
  "history-scan": ["git", "incident", "leaked", "credential", "revoked", "bfg", "purge"],
  "deps-scan": ["dependencies", "packages", "lockfile", "osv", "sca", "npm", "cargo"],
  "binary-scan": ["firmware", "elf", "executable", "sbom", "components"],
  inventory: ["components", "packages", "purl", "cpe", "bom"],
  "rule-library": ["rules", "packs", "detections", "signatures"],
  "quality-lab": ["benchmark", "precision", "recall", "accuracy", "ground truth"],
  "data-sources": ["providers", "nvd", "osv", "kev", "epss", "offline", "snapshots"],
  "export-center": ["sarif", "cyclonedx", "spdx", "vex", "report", "import"],
  verification: ["verify", "attest", "independent"],
  "compliance-center": ["iso", "gdpr", "unece", "nist", "controls", "readiness"],
  "report-studio": ["pdf", "html", "markdown", "csv", "disclosure"],
  "cve-research": ["cve", "nvd", "advisory", "vulnerability", "lookup"],
  assistant: ["ai", "chat", "ask", "llm", "agent"],
  settings: ["preferences", "config", "api key", "endpoint", "theme", "diagnostics"],
};

/** Every screen, as a command. */
export const NAVIGATION_COMMANDS: NavigateCommand[] = (
  Object.keys(PAGE_META) as Page[]
).map((page) => ({
  kind: "navigate",
  id: `navigate:${page}`,
  page,
  title: PAGE_META[page].title,
  group: PAGE_META[page].group,
  keywords: KEYWORDS[page],
}));

/**
 * Score one command against a query.
 *
 * Higher is better; `null` means it does not match at all. The ordering is
 * deliberate and follows what a person expects as they type:
 *
 *   1. an exact title
 *   2. a title that starts with what they typed
 *   3. a word in the title that starts with it
 *   4. a title that contains it anywhere
 *   5. a keyword match
 *
 * Subsequence matching ("cvr" -> "CVE Research") is deliberately *not*
 * included. It makes short queries match almost everything, and for a tool
 * where a command can start a scan or change a policy, a surprising match is
 * worse than no match.
 */
export function score(command: Command, query: string): number | null {
  const needle = query.trim().toLowerCase();
  if (!needle) return 0;

  const title = command.title.toLowerCase();
  if (title === needle) return 100;
  if (title.startsWith(needle)) return 80;
  if (title.split(/\s+/).some((word) => word.startsWith(needle))) return 60;
  if (title.includes(needle)) return 40;

  for (const keyword of command.keywords ?? []) {
    const lowered = keyword.toLowerCase();
    if (lowered === needle) return 30;
    if (lowered.startsWith(needle)) return 20;
    if (lowered.includes(needle)) return 10;
  }
  return null;
}

/**
 * Commands matching `query`, best first.
 *
 * Ties break alphabetically rather than by definition order, so the list does
 * not reshuffle for reasons the reader cannot see.
 */
export function filterCommands<T extends Command>(commands: T[], query: string): T[] {
  return commands
    .map((command) => ({ command, rank: score(command, query) }))
    .filter((entry): entry is { command: T; rank: number } => entry.rank !== null)
    .sort((left, right) => right.rank - left.rank || left.command.title.localeCompare(right.command.title))
    .map((entry) => entry.command);
}

/** Group matched commands for display, preserving rank order within a group. */
export function groupCommands<T extends Command>(commands: T[]): Array<[string, T[]]> {
  const groups = new Map<string, T[]>();
  for (const command of commands) {
    const existing = groups.get(command.group);
    if (existing) existing.push(command);
    else groups.set(command.group, [command]);
  }
  return [...groups.entries()];
}

/**
 * Move the highlighted index by `delta`, wrapping at both ends.
 *
 * Wrapping rather than clamping: a list navigated by keyboard should let a
 * single Up from the top reach the last item, which is how every other palette
 * behaves.
 */
export function moveSelection(current: number, delta: number, count: number): number {
  if (count <= 0) return 0;
  return (((current + delta) % count) + count) % count;
}

/**
 * Recent projects, as commands.
 *
 * The hint carries what is actually load-bearing when choosing between
 * codebases — how much is still open — rather than a timestamp nobody reads.
 * The path is a keyword so a directory name finds a project whose display name
 * is something else.
 */
export function projectCommands(
  projects: readonly RecentProjectLike[],
): ProjectCommand[] {
  return projects.map((project) => ({
    kind: "project",
    id: `project:${project.projectId}`,
    projectPath: project.canonicalPath,
    title: project.displayName,
    group: "Projects",
    keywords: [project.canonicalPath],
    hint: describeProjectState(project),
  }));
}

/** The subset of a recent project the palette needs. */
export interface RecentProjectLike {
  countsAvailable?: boolean | null;
  projectId: string;
  canonicalPath: string;
  displayName: string;
  openFindings: number;
  critical: number;
  high: number;
}

/**
 * What is still outstanding in a project, in a few characters.
 *
 * Severity counts lead because that is what decides where to go next; a project
 * with nothing open says so rather than showing a zero.
 */
export function describeProjectState(project: RecentProjectLike): string {
  if (project.countsAvailable === false) return "counts unavailable";
  if (project.openFindings === 0) return "clear";
  const parts: string[] = [];
  if (project.critical > 0) parts.push(`${project.critical} critical`);
  if (project.high > 0) parts.push(`${project.high} high`);
  if (parts.length === 0) return `${project.openFindings} open`;
  return `${parts.join(", ")} of ${project.openFindings}`;
}
