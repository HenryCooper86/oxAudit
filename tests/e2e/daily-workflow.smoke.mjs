// Daily workflow smoke: token onboarding without AI (and without any native
// Browse picker in headless mode), a real scan of the copied vulnerable pilot
// fixture, a persisted review decision, a corrected-fixture recheck, a real
// server process restart against the same data/config, reopening the saved run
// and review, and exporting that saved run through the UI as SARIF whose
// identity is verified on disk.
import { copyFile, readFile } from "node:fs/promises";
import path from "node:path";
import { test, expect, fixturesRoot, connectThroughGate, metric } from "./helpers.mjs";

test("onboarding, first scan, review, recheck, restart, reopen and SARIF export", async ({ page, backend }) => {
  test.setTimeout(300_000);
  const project = await backend.materializePilotProject("vulnerable", "project");
  const sarifPath = path.join(backend.root, "export", "source-run.sarif");

  // --- Token onboarding -------------------------------------------------
  await page.goto(backend.origin);
  const gate = page.getByRole("dialog");
  await expect(gate.getByRole("heading", { name: "Server access token" })).toBeVisible();
  await gate.getByLabel("Access token").fill(backend.token);
  await gate.getByRole("button", { name: "Connect" }).click();

  // --- First-launch wizard without AI and without native pickers --------
  const wizardTitle = page.locator("#readiness-wizard-title");
  await expect(wizardTitle).toBeVisible();
  await expect(wizardTitle).toHaveText("Welcome");
  await page.getByRole("button", { name: "Continue", exact: true }).click();

  await expect(wizardTitle).toHaveText("Core readiness");
  await expect(page.getByRole("button", { name: "Check again" })).toBeVisible();
  await page.getByRole("button", { name: "Continue", exact: true }).click();

  await expect(wizardTitle).toHaveText("Optional AI");
  await expect(page.getByText("No AI provider configured")).toBeVisible();
  await page.getByRole("button", { name: "Continue without AI" }).click();

  await expect(wizardTitle).toHaveText("Your first project");
  // Headless server mode: type a server path; the native Browse button must
  // not exist, and the input must say paths refer to the server's filesystem.
  await expect(page.getByRole("dialog").getByText("Paths refer to the server's filesystem.", { exact: false })).toBeVisible();
  await expect(page.getByRole("button", { name: "Browse…" })).toHaveCount(0);
  await page.getByLabel("First project folder").fill(project);
  await page.getByRole("button", { name: "Check project" }).click();

  // --- Real scan of the copied vulnerable fixture ------------------------
  const home = page.locator('section[aria-label="Project home"]');
  const check = home.getByRole("status").filter({ hasText: "Project check" });
  await expect(check).toContainText("Project check completed", { timeout: 120_000 });
  await expect(check).toContainText("Source: completed");
  await expect(check).toContainText("Dependencies: not applicable");
  // The workbench is fully functional without an AI provider.
  await expect(page.locator("footer")).toContainText("AI not configured");
  await home.getByRole("button", { name: "View source findings" }).click();

  const summary = page.locator('section[aria-label="Scan summary"]');
  await expect(summary).toBeVisible({ timeout: 60_000 });
  await expect(metric(summary, "Files")).toHaveText("1");
  await expect(metric(summary, "Secrets")).toHaveText("0");
  await expect(metric(summary, "Vulnerabilities")).toHaveText("1");

  const findings = page.getByRole("listbox", { name: "Findings" });
  const evalRow = findings.getByRole("option").filter({ hasText: "eval() usage" });
  await expect(evalRow).toBeVisible();
  await evalRow.click();
  await expect(page.getByRole("heading", { name: "eval() usage" })).toBeVisible();
  await expect(evalRow).toContainText("handler.js:4");

  // --- Persisted review decision ----------------------------------------
  await page.getByRole("button", { name: "Review finding" }).click();
  const reviewForm = page.locator('form[aria-label="Review finding"]');
  await reviewForm.locator("#review-state").selectOption("acceptedRisk");
  await reviewForm.locator("#review-reason").fill("Daily smoke: the inert fixture risk is accepted for this run.");
  await reviewForm.getByRole("button", { name: "Save review" }).click();
  await page.getByRole("tab", { name: /^Closed/ }).click();
  await expect(evalRow).toBeVisible();
  await expect(evalRow).toContainText("Accepted risk");
  await evalRow.click();
  await expect(page.locator('section[aria-labelledby="finding-review-summary"]')).toContainText("Accepted risk");

  // --- Corrected fixture, recheck verifies covered absence ---------------
  await copyFile(
    path.join(fixturesRoot, "corrected", "handler.js"),
    path.join(project, "handler.js"),
  );
  await page.getByRole("button", { name: "Recheck finding" }).click();
  const outcome = page.locator('section[aria-label="Finding recheck outcome"]');
  await expect(outcome.getByRole("status")).toContainText(
    "No longer detected in the covered file and rule family.",
    { timeout: 120_000 },
  );
  const originalRunId = ((await outcome.getByRole("button", { name: /^Original run / }).textContent()) ?? "")
    .replace(/^Original run\s*/, "")
    .trim();
  expect(originalRunId).toMatch(/^[0-9a-f-]{20,}$/i);

  // --- Real process restart with the same data and config ---------------
  await backend.restart();
  await page.goto(backend.origin);
  await expect(page.locator('aside[aria-label="Primary navigation"]')).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);

  // Reopen the project; the latest (corrected, empty) run restores first.
  await home.getByLabel("Project folder").fill(project);
  await home.getByRole("button", { name: "Open project" }).click();
  await home.getByRole("button", { name: "Source results" }).click();
  await expect(summary).toBeVisible({ timeout: 60_000 });
  await expect(metric(summary, "Files")).toHaveText("1");
  await expect(metric(summary, "Vulnerabilities")).toHaveText("0");
  await expect(page.getByRole("tab", { name: "Open 0", exact: true })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Resolved 1", exact: true })).toBeVisible();

  // Then reopen the original saved run and its persisted review decision.
  const history = page.locator('section[aria-labelledby="run-history-title"]');
  const originalRun = history.getByRole("button").filter({ hasText: "1 findings" });
  await expect(originalRun).toBeVisible();
  await originalRun.click();
  await page.getByRole("tab", { name: /^Closed/ }).click();
  await expect(evalRow).toBeVisible({ timeout: 60_000 });
  await expect(evalRow).toContainText("Accepted risk");
  await evalRow.click();
  await expect(page.locator('section[aria-labelledby="finding-review-summary"]')).toContainText("Accepted risk");

  // --- Export the saved source run through the UI ------------------------
  await page.getByRole("button", { name: "Export Center" }).click();
  const runSelect = page.getByLabel("Saved run");
  await expect(runSelect.locator(`option[value="${originalRunId}"]`)).toBeAttached({ timeout: 60_000 });
  await runSelect.selectOption(originalRunId);
  await page.getByLabel("Format").selectOption("sarif");
  await expect(page.getByRole("heading", { name: "SARIF 2.1.0 preview" })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText("Structure valid")).toBeVisible();
  await page.getByLabel("Export file on server").fill(sarifPath);
  await page.getByRole("button", { name: "Save to server" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Saved export to" })).toBeVisible({ timeout: 60_000 });

  // The saved file is the actual saved run: identity, coverage and review
  // travel together, and nothing about the transport or server leaks into it.
  const sarif = JSON.parse(await readFile(sarifPath, "utf8"));
  expect(sarif.version).toBe("2.1.0");
  expect(sarif.runs).toHaveLength(1);
  expect(sarif.runs[0].tool.driver.name).toBe("oxAudit");
  expect(sarif.runs[0].properties.oxAuditRunId).toBe(originalRunId);
  expect(sarif.runs[0].properties.oxAuditRunState).toBe("completed");
  expect(sarif.runs[0].invocations[0].executionSuccessful).toBe(true);
  expect(sarif.runs[0].results).toHaveLength(1);
  const result = sarif.runs[0].results[0];
  expect(result.ruleId).toBe("js-eval");
  expect(result.level).toBe("error");
  expect(result.locations[0].physicalLocation.artifactLocation.uri).toContain("handler.js");
  expect(result.suppressions?.[0]).toMatchObject({ kind: "external", status: "accepted" });
  expect(result.suppressions?.[0]?.justification).toContain("Daily smoke");
  const raw = await readFile(sarifPath, "utf8");
  expect(raw).not.toContain(backend.token);
  expect(raw).not.toContain(backend.proxy.url);
  expect(raw).not.toContain(backend.dataDir);
  expect(raw).not.toContain(backend.configDir);
  expect(raw).not.toContain(backend.root);
});
