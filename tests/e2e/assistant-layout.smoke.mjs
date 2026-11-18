// The AI Assistant's layout against a real oxaudit-server. The headless server
// does not run AI, so this checks the structure and the degraded state: the
// welcome, a composer that is present but disabled with the server's copy,
// the header toggles that open and close the Conversations and Activity
// panels (docked at desktop width, a drawer at 899px), and a document that
// never grows scrollbars of its own.
import { test, expect, connectThroughGate, skipReadinessWizard } from "./helpers.mjs";

/** The document and #root stay inside the viewport. */
function documentFits(page) {
  return page.evaluate(() => {
    const doc = document.documentElement;
    const root = document.getElementById("root");
    return (
      doc.scrollHeight <= doc.clientHeight + 1 &&
      doc.scrollWidth <= doc.clientWidth + 1 &&
      (!root || root.scrollHeight <= root.clientHeight + 1)
    );
  });
}

async function openAssistant(page, narrow) {
  if (narrow) await page.locator("#navigation-menu-button").click();
  await page
    .locator('aside[aria-label="Primary navigation"]')
    .getByRole("button", { name: "AI Assistant", exact: true })
    .click();
  await expect(page.locator("#assistant-composer")).toBeVisible();
}

for (const { width, height } of [
  { width: 1440, height: 900 },
  { width: 899, height: 700 },
]) {
  test(`assistant layout at ${width}x${height}: welcome, disabled composer, header panels, no document scroll`, async ({ page, backend }) => {
    test.setTimeout(120_000);
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(String(error)));
    // The gate helper expects the desktop sidebar, so connect wide, then resize.
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectThroughGate(page, backend);
    await skipReadinessWizard(page);
    await page.setViewportSize({ width, height });
    const narrow = width < 900;
    await openAssistant(page, narrow);

    // The shell header carries the page heading; the empty conversation welcomes.
    const header = page.locator("header").first();
    await expect(header.getByRole("heading", { level: 1, name: "AI Assistant" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Welcome to oxAudit" })).toBeVisible();
    await expect(page.getByText("What would you like to audit?")).toBeVisible();
    await expect(page.getByRole("button", { name: /^Project for this conversation:/ })).toBeVisible();

    // No AI in the server build: the composer is there but disabled, and says why.
    const composer = page.getByRole("textbox", { name: "Message the AI Assistant" });
    await expect(composer).toBeVisible();
    await expect(composer).toBeDisabled();
    await expect(composer).toHaveAttribute("placeholder", "AI is not available in the browser build");
    await expect(page.getByRole("alert").filter({ hasText: "AI is available in the oxAudit desktop app" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Open Settings" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Send message" })).toBeDisabled();
    await expect(page.getByText("Project reads run without asking; other tools ask for approval")).toBeVisible();

    // A starter chip fills the composer field even though sending is locked.
    await page.getByRole("button", { name: "Auth flow checklist" }).click();
    await expect(composer).toHaveValue(/checklist for reviewing an authentication flow/);

    // Both panels start closed and open from the header, one at a time.
    const sessions = page.getByRole("complementary", { name: "Chat sessions" });
    const activity = page.getByRole("complementary", { name: "Assistant activity" });
    await expect(sessions).toHaveCount(0);
    await expect(activity).toHaveCount(0);
    const conversationsToggle = header.getByRole("button", { name: "Conversations" });
    const activityToggle = header.getByRole("button", { name: "Activity" });

    await conversationsToggle.click();
    await expect(sessions).toBeVisible();
    await expect(sessions.getByRole("button", { name: "New chat", exact: true })).toBeVisible();
    await expect(conversationsToggle).toHaveAttribute("aria-pressed", "true");
    // oxFuzz's PanelShell: 320px against the right edge of the workspace.
    const dockBox = await page.locator("[data-assistant-panel]").boundingBox();
    expect(Math.round(dockBox.width)).toBe(320);
    expect(Math.round(dockBox.x + dockBox.width)).toBe(width);
    if (narrow) {
      // A drawer over the conversation, not a squeezed column.
      await expect(page.locator("[data-assistant-panel='drawer']")).toBeVisible();
      await expect(page.locator("#assistant-composer")).toBeVisible();
      expect((await page.locator("#assistant-composer").boundingBox()).width).toBeGreaterThan(600);
    } else {
      await expect(page.locator("[data-assistant-panel='docked']")).toBeVisible();
    }
    expect(await documentFits(page)).toBe(true);

    if (narrow) {
      // Escape closes the drawer and returns focus to its toggle.
      await page.keyboard.press("Escape");
      await expect(sessions).toHaveCount(0);
      await expect(conversationsToggle).toBeFocused();
    }

    await activityToggle.click();
    await expect(activity).toBeVisible();
    await expect(sessions).toHaveCount(0);
    await expect(activity.getByText("Idle")).toBeVisible();
    expect(await documentFits(page)).toBe(true);
    await activityToggle.click();
    await expect(activity).toHaveCount(0);
    await expect(activityToggle).toHaveAttribute("aria-pressed", "false");

    // Conversation search opens from the header too.
    await header.getByRole("button", { name: "Search conversation" }).click();
    await expect(page.getByRole("searchbox", { name: "Search this conversation" })).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("search", { name: "Search conversation" })).toHaveCount(0);

    expect(await documentFits(page)).toBe(true);
    expect(pageErrors).toEqual([]);
  });
}
