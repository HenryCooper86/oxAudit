import assert from "node:assert/strict";
import test from "node:test";
import { detectHost, detectPlatform } from "../src/lib/platform";

test("platform detection reads the navigator platform and user agent", () => {
  assert.equal(detectPlatform({ platform: "MacIntel", userAgent: "Mozilla/5.0 (Macintosh)" }), "macos");
  assert.equal(detectPlatform({ platform: "Win32", userAgent: "Mozilla/5.0 (Windows NT 10.0)" }), "windows");
  assert.equal(detectPlatform({ platform: "Linux x86_64", userAgent: "Mozilla/5.0 (X11; Linux)" }), "linux");
  assert.equal(detectPlatform({ platform: "", userAgent: "" }), "unknown");
  assert.equal(detectPlatform(null), "unknown");
});

test("only the Tauri webview counts as the desktop host", () => {
  // The headless server's browser build must never reserve room for
  // traffic lights or register drag regions.
  assert.equal(detectHost({ __TAURI_INTERNALS__: {} }), "tauri");
  assert.equal(detectHost({}), "web");
  assert.equal(detectHost(null), "web");
});
