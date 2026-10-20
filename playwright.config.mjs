// Daily smoke: the built frontend in real Chromium against a real
// oxaudit-server process. Each test owns its backend lifecycle (one suite
// scenario restarts the process mid-test), so there is no Playwright
// `webServer`; the per-test backend fixture in tests/e2e/helpers.mjs spawns
// src-tauri/target/debug/oxaudit-server with isolated data/config dirs.
//
// The suite is deliberately serial: one Chromium worker keeps the backend
// lifecycle deterministic and keeps the loopback-only environment (server,
// refusing enrichment proxy, temp fixtures) free of cross-test interference.
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests/e2e",
  testMatch: "**/*.smoke.mjs",
  outputDir: "test-results",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 300_000,
  expect: { timeout: 15_000 },
  reporter: [
    ["list"],
    ["html", { outputFolder: "playwright-report", open: "never" }],
  ],
  use: {
    headless: true,
    actionTimeout: 20_000,
    navigationTimeout: 30_000,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
    // All browser traffic is loopback to the spawned server; never route it
    // through a host/CI proxy that the environment may define.
    launchOptions: { args: ["--no-proxy-server"] },
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
