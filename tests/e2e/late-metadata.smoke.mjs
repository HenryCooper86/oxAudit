// Saved-run request ownership: superseded history metadata must neither leave
// findings blank after target changes nor replace a fresh completed scan.
import { test, expect, connectThroughGate, skipReadinessWizard, holdInvokes, metric } from "./helpers.mjs";

async function afterResponsePaint(page, response) {
  await (await response).finished();
  // Let response parsing and React's queued render run before checking that
  // a stale result did not replace the already visible current receipt.
  await page.evaluate(() => {
    const painted = Promise.withResolvers();
    requestAnimationFrame(() => requestAnimationFrame(painted.resolve));
    return painted.promise;
  });
}

test("delayed saved-run metadata cannot blank findings or replace a fresh scan", async ({ page, backend }) => {
  const vulnerable = await backend.materializePilotProject("vulnerable", "project-a");
  const other = await backend.materializePilotProject("corrected", "project-b");
  await connectThroughGate(page, backend);
  await skipReadinessWizard(page);
  await page.getByRole("button", { name: "Source Scan", exact: true }).click();
  const target = page.getByLabel("Project folder path");
  const summary = page.getByRole("region", { name: "Scan summary", exact: true });
  const history = page.getByRole("region", { name: "Run history", exact: true });
  const finding = page.getByRole("listbox", { name: "Findings" }).getByRole("option").filter({ hasText: "eval() usage" });
  const context = page.getByRole("region", { name: "Finding run context" });
  const observedRun = metric(context, "Observed in run");
  await target.fill(vulnerable);
  await page.getByRole("button", { name: "Run scan", exact: true }).click();
  await expect(finding).toBeVisible({ timeout: 60_000 });
  const firstRun = (await observedRun.innerText()).trim();
  expect(firstRun).toMatch(/^[0-9a-f-]{36}$/i);

  // A second saved run lets the old history response differ from the current
  // receipt even though both legitimately contain the same finding.
  await page.getByRole("button", { name: "Run scan", exact: true }).click();
  await expect(observedRun).not.toHaveText(firstRun);
  await expect(history.getByRole("button")).toHaveCount(2);
  const currentRun = (await observedRun.innerText()).trim();
  expect(currentRun).toMatch(/^[0-9a-f-]{36}$/i);
  const oldMetadata = () => holdInvokes(page, "load_source_run_metadata", {
    matcher: request => request.postDataJSON()?.runId === firstRun,
  });

  const changingTarget = oldMetadata();
  try {
    await changingTarget.ready;
    await history.getByRole("button").last().click();
    await changingTarget.waitForHeld();
    await target.fill(other);
    await expect(summary).toHaveCount(0);
    await target.fill(vulnerable);
    await expect(finding).toBeVisible();
    await expect(observedRun).toHaveText(currentRun);
    const landed = page.waitForResponse(response =>
      response.url().endsWith("/api/invoke/load_source_run_metadata") &&
      response.request().postDataJSON()?.runId === firstRun);
    changingTarget.release();
    await afterResponsePaint(page, landed);
    await expect(finding).toBeVisible();
    await expect(observedRun).toHaveText(currentRun);
  } finally {
    await changingTarget.dispose();
  }

  const beforeScan = oldMetadata();
  const runningScan = holdInvokes(page, "scan_project");
  try {
    await Promise.all([beforeScan.ready, runningScan.ready]);
    await history.getByRole("button").last().click();
    await beforeScan.waitForHeld();
    await page.getByRole("button", { name: "Run scan", exact: true }).click();
    await runningScan.waitForHeld();
    for (const row of await history.getByRole("button").all()) await expect(row).toBeDisabled();
    runningScan.release();
    await expect(finding).toBeVisible({ timeout: 60_000 });
    await expect(observedRun).not.toHaveText(currentRun);
    const freshRun = (await observedRun.innerText()).trim();
    expect(freshRun).toMatch(/^[0-9a-f-]{36}$/i);
    await expect(history.getByRole("button")).toHaveCount(3);
    const landed = page.waitForResponse(response =>
      response.url().endsWith("/api/invoke/load_source_run_metadata") &&
      response.request().postDataJSON()?.runId === firstRun);
    beforeScan.release();
    await afterResponsePaint(page, landed);
    await expect(observedRun).toHaveText(freshRun);
    await expect(finding).toBeVisible();
    await expect(metric(summary, "Files")).toHaveText("1");
    await expect(metric(summary, "Vulnerabilities")).toHaveText("1");
    await expect(page.getByRole("alert")).toHaveCount(0);
  } finally {
    await beforeScan.dispose();
    await runningScan.dispose();
  }
});
