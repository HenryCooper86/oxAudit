// YARA rules and Nuclei templates through the real server: import an original
// YARA rule file and an original file-protocol template through Rule Library
// (typed server paths, no native dialogs), run a YARA scan and a local-path
// template scan against a temp folder, read the match and its offset, and
// check that Live targets is reported unavailable (the harness starts the
// server without --allow-live-targets) without any scan_templates request
// being sent for it.
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { test, expect, connectThroughGate, skipReadinessWizard } from "./helpers.mjs";

const YARA_RULE = `rule Smoke_Marker
{
  meta:
    severity = "high"
    description = "Original rule written for the browser smoke"
  strings:
    $marker = "OXAUDIT-SMOKE-MARKER"
  condition:
    $marker
}
`;

const TEMPLATE = `id: smoke-file-token
info:
  name: Smoke file token
  author: oxaudit-smoke
  severity: low
  description: Original template written for the browser smoke.
file:
  - extensions:
      - conf
    matchers:
      - type: word
        words:
          - "OXAUDIT-SMOKE-TEMPLATE"
`;

test("import YARA rules and a Nuclei template, scan a folder, and see live targets refused", async ({ page, backend }) => {
  test.setTimeout(300_000);
  const rules = path.join(backend.root, "yara-rules");
  const templates = path.join(backend.root, "nuclei-templates");
  const target = path.join(backend.root, "scan-target");
  await Promise.all([rules, templates, target].map((directory) => mkdir(directory, { recursive: true })));
  await writeFile(path.join(rules, "smoke.yar"), YARA_RULE);
  await writeFile(path.join(templates, "smoke.yaml"), TEMPLATE);
  // The YARA marker sits at byte offset 10; the template token is on line 2.
  await writeFile(path.join(target, "sample.dat"), "0123456789OXAUDIT-SMOKE-MARKER\n");
  await writeFile(path.join(target, "app.conf"), "name=demo\nkey=OXAUDIT-SMOKE-TEMPLATE\n");

  const templateScans = [];
  page.on("request", (request) => {
    if (request.url().includes("/api/invoke/scan_templates")) templateScans.push(request.url());
  });

  await connectThroughGate(page, backend);
  await skipReadinessWizard(page);
  const nav = page.locator('aside[aria-label="Primary navigation"]');

  // --- Import both packs through Rule Library --------------------------------
  await nav.getByRole("button", { name: "Rule Library" }).click();
  await expect(page.getByRole("button", { name: "Choose file…" })).toHaveCount(0);
  await expect(page.getByText("Paths refer to the server's filesystem.", { exact: false }).first()).toBeVisible();

  await page.getByLabel("Pack path on server").fill(rules);
  await page.getByRole("button", { name: "Inspect" }).click();
  const preview = page.getByRole("group", { name: "Pack preview" });
  await expect(preview).toContainText("Rules that will run");
  await page.getByLabel("Name", { exact: true }).fill("Smoke YARA");
  await page.getByLabel("Licence", { exact: true }).fill("Apache-2.0");
  await page.getByRole("button", { name: "Install pack" }).click();
  await expect(page.getByText("Smoke YARA").first()).toBeVisible();

  await page.getByLabel("Pack kind").selectOption("nuclei");
  await page.getByLabel("Pack path on server").fill(templates);
  await page.getByRole("button", { name: "Inspect" }).click();
  await expect(preview).toContainText("Templates that will run");
  await page.getByLabel("Name", { exact: true }).fill("Smoke templates");
  await page.getByLabel("Licence", { exact: true }).fill("Apache-2.0");
  await page.getByRole("button", { name: "Install pack" }).click();
  await expect(page.getByText("Smoke templates").first()).toBeVisible();

  // --- YARA scan -------------------------------------------------------------
  await nav.getByRole("button", { name: "YARA Scan" }).click();
  await page.getByLabel("YARA target").fill(target);
  await expect(page.getByText(/Packs \(1 of 1 selected\)/)).toBeVisible();
  await page.getByRole("button", { name: "Run YARA scan" }).click();
  const yaraList = page.getByRole("list", { name: "YARA matches" });
  await expect(yaraList).toContainText("Smoke_Marker", { timeout: 120_000 });
  await yaraList.getByRole("button", { name: /Smoke_Marker/ }).click();
  const strings = page.getByRole("table", { name: "Matched strings" });
  await expect(strings).toContainText("$marker");
  await expect(strings).toContainText("0xa (10)");
  await expect(strings).toContainText("OXAUDIT-SMOKE-MARKER");

  // --- Local-path template scan ----------------------------------------------
  await nav.getByRole("button", { name: "Template Scan" }).click();
  await page.getByLabel("Template target").fill(target);
  await expect(page.getByText(/Packs \(1 of 1 selected\)/)).toBeVisible();
  await page.getByRole("button", { name: "Run template scan" }).click();
  const templateList = page.getByRole("list", { name: "Template matches" });
  await expect(templateList).toContainText("Smoke file token", { timeout: 120_000 });
  await templateList.getByRole("button", { name: /Smoke file token/ }).click();
  await expect(page.getByRole("list", { name: "Matched lines" })).toContainText("key=OXAUDIT-SMOKE-TEMPLATE");
  expect(templateScans).toHaveLength(1);

  // --- Live targets are refused on a server started without the flag ---------
  await page.getByRole("radio", { name: "Live targets" }).check({ force: true });
  await expect(page.getByText("Live targets are turned off on this server")).toBeVisible();
  await expect(page.getByText("--allow-live-targets", { exact: false })).toBeVisible();
  await expect(page.getByLabel("Targets", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Run (live|template) scan/ })).toBeDisabled();
  expect(templateScans).toHaveLength(1);
});
