import assert from "node:assert/strict";
import test from "node:test";
import {
  LEGACY_NAVIGATION_COLLAPSED_CACHE_KEY,
  NAVIGATION_HIDDEN_CACHE_KEY,
  parseNavigationHidden,
  resolveNavigationHidden,
} from "../src/lib/navigationPreference";
import {
  panelCollapsedCacheKey,
  parsePanelCollapsed,
} from "../src/lib/panelPreference";

test("sidebar visibility preferences accept only explicit booleans", () => {
  assert.equal(parseNavigationHidden("true"), true);
  assert.equal(parseNavigationHidden("false"), false);
  assert.equal(parseNavigationHidden("collapsed"), null);
  assert.equal(parseNavigationHidden(null), null);
});

test("the sidebar is shown until the user hides it, on every page", () => {
  // There is no icon rail and no page-specific default any more (the
  // Assistant used to start compact); the user's last choice is the state.
  assert.equal(resolveNavigationHidden(null), false);
  assert.equal(resolveNavigationHidden(false), false);
  assert.equal(resolveNavigationHidden(true), true);
});

test("the hidden preference uses a new key so a stored icon-rail choice cannot hide navigation", () => {
  assert.equal(NAVIGATION_HIDDEN_CACHE_KEY, "oxaudit.navigationHidden.v1");
  assert.notEqual(NAVIGATION_HIDDEN_CACHE_KEY, LEGACY_NAVIGATION_COLLAPSED_CACHE_KEY);
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
