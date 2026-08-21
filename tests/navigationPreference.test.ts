import assert from "node:assert/strict";
import test from "node:test";
import {
  parseNavigationCollapsed,
  resolveNavigationCollapsed,
} from "../src/lib/navigationPreference";
import {
  panelCollapsedCacheKey,
  parsePanelCollapsed,
} from "../src/lib/panelPreference";

test("navigation collapse preferences accept only explicit booleans", () => {
  assert.equal(parseNavigationCollapsed("true"), true);
  assert.equal(parseNavigationCollapsed("false"), false);
  assert.equal(parseNavigationCollapsed("collapsed"), null);
  assert.equal(parseNavigationCollapsed(null), null);
});

test("Assistant defaults to compact until the user chooses a shell width", () => {
  assert.equal(resolveNavigationCollapsed(null, true), true);
  assert.equal(resolveNavigationCollapsed(null, false), false);
  assert.equal(resolveNavigationCollapsed(false, true), false);
  assert.equal(resolveNavigationCollapsed(true, false), true);
});

test("secondary panel preferences use stable versioned keys", () => {
  assert.equal(
    panelCollapsedCacheKey("assistant-sessions"),
    "oxaudit.panel.assistant-sessions.collapsed.v1",
  );
  assert.equal(parsePanelCollapsed("true"), true);
  assert.equal(parsePanelCollapsed("false"), false);
  assert.equal(parsePanelCollapsed("invalid"), null);
});
