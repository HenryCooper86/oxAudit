import { mkdir } from "node:fs/promises";
import path from "node:path";
import { test, expect, connectThroughGate, skipReadinessWizard } from "./helpers.mjs";

test("portfolio retries a failed load and schedules a project beyond the first fifty", async ({ page, backend }) => {
  for (let index = 0; index < 55; index += 1) {
    const project = path.join(backend.root, `portfolio-${String(index).padStart(3, "0")}`);
    await mkdir(project);
    const response = await page.request.post(`${backend.origin}/api/invoke/inspect_source_project`, {
      headers: { authorization: `Bearer ${backend.token}` }, data: { path: project },
    });
    expect((await response.json()).ok).toBe(true);
  }
  await connectThroughGate(page, backend);
  await skipReadinessWizard(page);
  let failed = false;
  await page.route("**/api/invoke/list_source_projects", async route => {
    if (!failed && route.request().postDataJSON()?.limit === 51) {
      failed = true;
      await route.fulfill({ status: 503, body: "Temporary test outage" });
    } else await route.continue();
  });
  await page.getByRole("button", { name: "Portfolio", exact: true }).click();
  await expect(page.getByRole("button", { name: "Retry loading portfolio" })).toBeVisible();
  await page.getByRole("button", { name: "Retry loading portfolio" }).click();
  await expect(page.getByRole("listitem")).toHaveCount(50);
  await page.getByRole("button", { name: "Next page of projects" }).click();
  await expect(page.getByRole("listitem")).toHaveCount(5);
  const oldest = page.getByRole("listitem").filter({ hasText: "portfolio-000" });
  await oldest.getByRole("button", { name: "Schedule daily" }).click();
  await expect(oldest.getByRole("switch", { name: "Rescheduling" })).toBeChecked();
  await page.getByRole("button", { name: "Previous page of projects" }).click();
  await expect(page.getByRole("listitem")).toHaveCount(50);
});
