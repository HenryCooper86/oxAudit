import assert from "node:assert/strict";
import test from "node:test";
import { NAVIGATION_COMMANDS } from "../src/lib/commandPalette";
import { NAVIGATION_SECTIONS, PAGE_META, SHELL_HEADING_PAGES, type Page } from "../src/lib/workbench";
import { selectHeaderActions, useHeaderActionStore } from "../src/lib/headerActions";

test("every page appears exactly once in the sidebar, Settings in its footer", () => {
  const listed = NAVIGATION_SECTIONS.flatMap((section) => section.pages);
  const all = Object.keys(PAGE_META) as Page[];
  assert.equal(new Set(listed).size, listed.length, "a page is listed twice");
  assert.deepEqual([...listed, "settings"].sort(), [...all].sort());
});

test("the sidebar groups, PAGE_META groups and command palette groups agree", () => {
  for (const section of NAVIGATION_SECTIONS) {
    for (const page of section.pages) {
      assert.equal(PAGE_META[page].group, section.group, `${page} is grouped differently`);
    }
  }
  assert.equal(PAGE_META.settings.group, "System");
  for (const command of NAVIGATION_COMMANDS) {
    assert.equal(command.group, PAGE_META[command.page].group);
  }
  assert.deepEqual(
    NAVIGATION_SECTIONS.map((section) => section.group),
    ["Workspace", "Scanning", "Results", "Intelligence", "Quality"],
  );
});

test("only pages without a ToolPage take their h1 from the shell header", () => {
  assert.deepEqual([...SHELL_HEADING_PAGES], ["assistant"]);
});

test("header actions are kept per owner, in registration order, and cleared by owner", () => {
  const noop = () => {};
  const icon = (() => null) as never;
  const store = useHeaderActionStore.getState();
  store.setActions("first", [{ id: "a", label: "A", icon, onSelect: noop }]);
  store.setActions("second", [{ id: "b", label: "B", icon, pressed: true, onSelect: noop }]);
  store.setActions("first", [{ id: "a2", label: "A2", icon, onSelect: noop }]);
  assert.deepEqual(selectHeaderActions(useHeaderActionStore.getState()).map((action) => action.id), ["a2", "b"]);
  useHeaderActionStore.getState().clearActions("first");
  assert.deepEqual(selectHeaderActions(useHeaderActionStore.getState()).map((action) => action.id), ["b"]);
  useHeaderActionStore.getState().clearActions("second");
  assert.deepEqual(selectHeaderActions(useHeaderActionStore.getState()), []);
});
