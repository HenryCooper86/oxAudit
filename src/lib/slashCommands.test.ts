import { describe, expect, it } from "vitest";
import {
  SLASH_COMMANDS,
  matchingSlashCommands,
  slashQuery,
} from "./slashCommands";

describe("slashQuery", () => {
  it("returns null when the input is not a slash command", () => {
    expect(slashQuery("")).toBeNull();
    expect(slashQuery("how do I scan this?")).toBeNull();
    expect(slashQuery("run /scan please")).toBeNull();
  });

  it("strips the leading slash and returns the query", () => {
    expect(slashQuery("/")).toBe("");
    expect(slashQuery("/scan")).toBe("scan");
    expect(slashQuery("  /cve")).toBe("cve");
  });
});

describe("matchingSlashCommands", () => {
  it("lists every command for a bare slash", () => {
    expect(matchingSlashCommands("/")).toEqual(SLASH_COMMANDS);
    expect(matchingSlashCommands("")).toEqual([]);
  });

  it("prefix-matches the command name", () => {
    expect(matchingSlashCommands("/s").map((command) => command.id)).toEqual([
      "/scan",
    ]);
    expect(matchingSlashCommands("/c").map((command) => command.id)).toEqual([
      "/cve",
      "/clear",
      "/copy",
    ]);
    expect(matchingSlashCommands("/cle").map((command) => command.id)).toEqual([
      "/clear",
    ]);
  });

  it("returns nothing for an unknown command", () => {
    expect(matchingSlashCommands("/nope")).toEqual([]);
  });
});
