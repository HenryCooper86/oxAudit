import { describe, expect, test } from "vitest";

import {
  NAVIGATION_COMMANDS,
  describeProjectState,
  projectCommands,
  filterCommands,
  groupCommands,
  moveSelection,
  score,
  type Command,
} from "./commandPalette";

const command = (title: string, keywords: string[] = []): Command => ({
  id: title,
  title,
  group: "Test",
  keywords,
});

describe("score", () => {
  test("ranks an exact title above a prefix above a substring", () => {
    const exact = score(command("Inventory"), "inventory");
    const prefix = score(command("Inventory Manager"), "inventory");
    const substring = score(command("Package Inventory Table"), "ventory");
    expect(exact!).toBeGreaterThan(prefix!);
    expect(prefix!).toBeGreaterThan(substring!);
  });

  test("matches a word inside a multi-word title", () => {
    // Someone types "research", not "cve research".
    expect(score(command("CVE Research"), "research")).not.toBeNull();
  });

  test("ranks a title match above a keyword match", () => {
    const byTitle = score(command("Export Center"), "export");
    const byKeyword = score(command("Report Studio", ["export"]), "export");
    expect(byTitle!).toBeGreaterThan(byKeyword!);
  });

  test("ignores case and surrounding whitespace", () => {
    expect(score(command("Settings"), "  SETTINGS  ")).toBe(score(command("Settings"), "settings"));
  });

  test("an empty query matches everything equally", () => {
    // Opening the palette should show the full list, not an arbitrary subset.
    expect(score(command("Anything"), "")).toBe(0);
    expect(score(command("Anything"), "   ")).toBe(0);
  });

  test("returns null rather than a weak score when nothing matches", () => {
    expect(score(command("Settings"), "zzzz")).toBeNull();
  });

  test("does not match a scattered subsequence", () => {
    // "cvr" matching "CVE Research" would also make short queries match almost
    // everything. For a tool where a command can change a decision, a
    // surprising match is worse than no match.
    expect(score(command("CVE Research"), "cvr")).toBeNull();
  });
});

describe("filterCommands", () => {
  test("returns matches best first", () => {
    const commands = [
      command("Report Studio", ["export"]),
      command("Export Center"),
      command("Inventory"),
    ];
    const [first, second, ...rest] = filterCommands(commands, "export");
    expect(first.title).toBe("Export Center");
    expect(second.title).toBe("Report Studio");
    expect(rest).toHaveLength(0);
  });

  test("breaks ties alphabetically so the list does not reshuffle unpredictably", () => {
    const commands = [command("Zebra"), command("Alpha"), command("Middle")];
    expect(filterCommands(commands, "").map((entry) => entry.title)).toEqual([
      "Alpha",
      "Middle",
      "Zebra",
    ]);
  });

  test("an empty query returns every command", () => {
    expect(filterCommands(NAVIGATION_COMMANDS, "")).toHaveLength(NAVIGATION_COMMANDS.length);
  });

  test("a query matching nothing returns nothing rather than everything", () => {
    // Falling back to the full list on no match is how a palette runs the
    // wrong thing when someone types and presses Enter quickly.
    expect(filterCommands(NAVIGATION_COMMANDS, "qqqqzzz")).toHaveLength(0);
  });
});

describe("navigation commands", () => {
  test("every screen is reachable", () => {
    // A screen missing from the palette is a screen only reachable by mouse.
    expect(NAVIGATION_COMMANDS.length).toBeGreaterThanOrEqual(15);
    expect(new Set(NAVIGATION_COMMANDS.map((entry) => entry.page)).size).toBe(
      NAVIGATION_COMMANDS.length,
    );
  });

  test("every command has a unique id", () => {
    const ids = NAVIGATION_COMMANDS.map((entry) => entry.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("vocabulary from other scanners finds the right screen", () => {
    const find = (query: string) => filterCommands(NAVIGATION_COMMANDS, query)[0]?.page;
    // Someone arriving from another tool types the format, not our screen name.
    expect(find("sarif")).toBe("export-center");
    expect(find("lockfile")).toBe("deps-scan");
    expect(find("precision")).toBe("quality-lab");
    expect(find("epss")).toBe("data-sources");
  });
});

describe("groupCommands", () => {
  test("keeps commands in rank order within a group", () => {
    const grouped = groupCommands([
      { id: "a", title: "A", group: "One" },
      { id: "b", title: "B", group: "Two" },
      { id: "c", title: "C", group: "One" },
    ]);
    expect(grouped.map(([name]) => name)).toEqual(["One", "Two"]);
    expect(grouped[0][1].map((entry) => entry.id)).toEqual(["a", "c"]);
  });

  test("an empty match set produces no groups", () => {
    expect(groupCommands([])).toEqual([]);
  });
});

describe("moveSelection", () => {
  test("wraps past the end and before the start", () => {
    // A single Up from the top should reach the last item, as every other
    // palette behaves.
    expect(moveSelection(2, 1, 3)).toBe(0);
    expect(moveSelection(0, -1, 3)).toBe(2);
  });

  test("moves normally in the middle of the list", () => {
    expect(moveSelection(0, 1, 3)).toBe(1);
    expect(moveSelection(2, -1, 3)).toBe(1);
  });

  test("stays at zero when there is nothing to select", () => {
    // Guards a modulo by zero when the query matches nothing.
    expect(moveSelection(0, 1, 0)).toBe(0);
    expect(moveSelection(5, -1, 0)).toBe(0);
  });
});

describe("project commands", () => {
  const project = (overrides: Partial<Parameters<typeof projectCommands>[0][number]> = {}) => ({
    projectId: "p1",
    canonicalPath: "/Users/analyst/clients/acme/api",
    displayName: "api",
    openFindings: 0,
    critical: 0,
    high: 0,
    ...overrides,
  });

  test("a project is findable by its directory path, not just its name", () => {
    // Half a dozen clients each have a directory called "api". The path is how
    // a person tells them apart.
    const commands = projectCommands([project()]);
    expect(filterCommands(commands, "acme")).toHaveLength(1);
  });

  test("a project command carries the path needed to switch to it", () => {
    const [command] = projectCommands([project()]);
    expect(command.kind).toBe("project");
    expect(command.projectPath).toBe("/Users/analyst/clients/acme/api");
  });

  test("projects and screens coexist in one list", () => {
    const combined = [...projectCommands([project({ displayName: "inventory-api" })]), ...NAVIGATION_COMMANDS];
    const groups = groupCommands(filterCommands(combined, "inventory")).map(([name]) => name);
    expect(groups).toContain("Projects");
    expect(groups.length).toBeGreaterThan(1);
  });

  test("the hint leads with severity, because that decides where to go next", () => {
    expect(describeProjectState(project({ openFindings: 12, critical: 2, high: 3 }))).toBe(
      "2 critical, 3 high of 12",
    );
    expect(describeProjectState(project({ openFindings: 4, high: 1 }))).toBe("1 high of 4");
  });

  test("a project with nothing open says so rather than showing a zero", () => {
    expect(describeProjectState(project())).toBe("clear");
  });

  test("open findings with no severity breakdown still report a count", () => {
    expect(describeProjectState(project({ openFindings: 5 }))).toBe("5 open");
  });
});
