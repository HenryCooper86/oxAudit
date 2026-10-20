// Lifecycle and transport-failure smoke: cancelling a dependency check before
// its command reaches the server keeps a neutral cancelled state with the
// prior saved evidence intact (no fake advisories), and a transient transport
// failure in the Export Center is recovered by the same-page retry, ending in
// a real validated file on disk.
import { readFile } from "node:fs/promises";
import path from "node:path";
import {
  test,
  expect,
  connectThroughGate,
  skipReadinessWizard,
  holdInvokes,
  failFirstInvoke,
  metric,
} from "./helpers.mjs";

test("cancel-before-registration and export retry after a transient 503", async ({ page, backend }) => {
  test.setTimeout(240_000);
  const depsProject = await backend.materializeEmptyLockfileProject("deps-project");
  const exportPath = path.join(backend.root, "export", "deps-run.sarif");

  // --- Completed empty inventory is the prior saved evidence -------------
  await connectThroughGate(page, backend);
  await skipReadinessWizard(page);
  await page.getByRole("button", { name: "Dependencies", exact: true }).click();
  await page.getByLabel("Project folder path").fill(depsProject);
  await page.getByText("Offline (use exact saved OSV queries only)").click();
  await expect(page.getByRole("switch", { name: "Offline (use exact saved OSV queries only)" })).toBeChecked();
  await page.getByRole("button", { name: "Check dependencies", exact: true }).click();

  const summary = page.locator('section[aria-label="Dependency scan summary"]');
  await expect(summary).toBeVisible({ timeout: 120_000 });
  await expect(metric(summary, "Lockfiles")).toHaveText("1");
  await expect(metric(summary, "Packages found")).toHaveText("0");
  await expect(metric(summary, "Packages checked")).toHaveText("0");
  await expect(metric(summary, "Vulnerabilities")).toHaveText("0");
  await expect(page.getByText("No packages to query")).toBeVisible();
  const evidence = page.getByRole("region", { name: "Dependency evidence summary" });
  await evidence.getByRole("button", { name: "Evidence details" }).click();
  const originalRunId = (await evidence.getByText(/^Run ID:/).locator("span").innerText()).trim();
  expect(originalRunId).toMatch(/^(run_)?[0-9a-f-]{36}$/i);

  // --- Cancel the next check before its command reaches the server ------
  const heldScan = holdInvokes(page, "scan_dependencies");
  await heldScan.ready;
  try {
    await page.getByRole("button", { name: "Check dependencies", exact: true }).click();
    await heldScan.waitForHeld(1);
    const cancellation = page.waitForResponse(response => response.url().endsWith("/api/invoke/cancel_scan_work"));
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    expect(await (await cancellation).json()).toMatchObject({ ok: true, data: true });
    await expect(evidence.getByRole("status")).toContainText("Cancellation requested");

    const commandSettled = page.waitForResponse(
      (response) => response.url().endsWith("/api/invoke/scan_dependencies"),
      { timeout: 30_000 },
    );
    heldScan.release();
    const cancelledCommand = await (await commandSettled).json();
    expect(cancelledCommand.ok).toBe(false);
    const message = typeof cancelledCommand.error === "string" ? cancelledCommand.error : cancelledCommand.error?.message;
    expect(message).toMatch(/cancelled/i);

    // Neutral cancelled state: the cancelled command never became a failure,
    // the earlier evidence is still displayed, and no advisories were invented.
    await expect(evidence.getByRole("status")).toContainText("Latest operation cancelled", { timeout: 60_000 });
    await expect(summary).toBeVisible();
    await expect(metric(summary, "Vulnerabilities")).toHaveText("0");
    await expect(page.getByText("No packages to query")).toBeVisible();
    await expect(page.getByText("Dependency checking failed")).toHaveCount(0);
    await expect(page.locator('section[aria-label="Dependency vulnerabilities"]')).toHaveCount(0);
  } finally {
    await heldScan.dispose();
  }

  // --- Export Center: transient transport failure, same-page retry ------
  const listFault = failFirstInvoke(page, "list_canonical_runs");
  const previewFault = failFirstInvoke(page, "preview_run_export", {
    status: 200,
    body: "{invalid-json",
  });
  await Promise.all([listFault.ready, previewFault.ready]);
  try {
    await page.getByRole("button", { name: "Export Center" }).click();
    await expect(page.getByRole("alert")).toContainText("The server returned 503.");
    await page.getByRole("button", { name: "Retry loading runs", exact: true }).click();
    await expect(page.getByText("Export preview is unavailable")).toBeVisible({ timeout: 60_000 });
    await page.getByRole("button", { name: "Retry preview" }).click();
    await expect(page.getByRole("heading", { name: "oxAudit JSON preview" })).toBeVisible({ timeout: 60_000 });

    await expect(page.getByLabel("Saved run")).toHaveValue(originalRunId);
    await page.getByLabel("Format").selectOption("sarif");
    await expect(page.getByRole("heading", { name: "SARIF 2.1.0 preview" })).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText("Structure valid")).toBeVisible();
    await page.getByLabel("Export file on server").fill(exportPath);
    await page.getByRole("button", { name: "Save to server" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Saved export to" })).toBeVisible({ timeout: 60_000 });

    // The retry produced a real file describing the actual saved run.
    const sarif = JSON.parse(await readFile(exportPath, "utf8"));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].properties.oxAuditRunId).toBe(originalRunId);
    expect(sarif.runs[0].properties.oxAuditRunState).toBe("completed");
    expect(sarif.runs[0].invocations[0].executionSuccessful).toBe(true);
    expect(sarif.runs[0].results).toEqual([]);
    const raw = await readFile(exportPath, "utf8");
    expect(raw).not.toContain(backend.token);
    expect(raw).not.toContain(backend.proxy.url);
    expect(raw).not.toContain(backend.dataDir);
    expect(raw).not.toContain(backend.root);
  } finally {
    await previewFault.dispose();
    await listFault.dispose();
  }
});
