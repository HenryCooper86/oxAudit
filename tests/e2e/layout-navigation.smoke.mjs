// Layout and navigation regression: the shell stays fixed to the viewport
// (only the workspace scrolls), long finding lists flow into that single
// scroll instead of nesting their own, keyboard navigation keeps the selected
// row visible without stealing focus, explicit activation reveals the detail
// pane, pagination returns the reader to the top of the results, and the
// 900px/899px navigation boundary collapses/expands and drawers correctly.
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { test, expect, connectThroughGate, skipReadinessWizard } from "./helpers.mjs";

const FINDING_COUNT = 120;

/** Owned inert temp source fixture with `count` distinct js-eval call sites. */
async function materializeEvalFixture(backend, count) {
  const directory = path.join(backend.root, "eval-fixture");
  await mkdir(directory, { recursive: true });
  for (let i = 1; i <= count; i++) {
    await writeFile(
      path.join(directory, `finding-${String(i).padStart(3, "0")}.js`),
      `// Inert scan fixture. Do not import or execute this file.\nexport function handler${i}(input) {\n  return eval(input);\n}\n`,
    );
  }
  return directory;
}

/** Geometry of `selector` relative to the workspace scrollport (actual DOM). */
function inMainView(page, selector) {
  return page.evaluate((sel) => {
    const el = document.querySelector(sel);
    const main = document.getElementById("main-content");
    if (!el || !main) return { found: false };
    const r = el.getBoundingClientRect();
    const m = main.getBoundingClientRect();
    return {
      found: true,
      top: r.top,
      bottom: r.bottom,
      mainTop: m.top,
      mainBottom: m.bottom,
      inView: r.top >= m.top - 1 && r.bottom <= m.bottom + 1,
    };
  }, selector);
}

function headerTop(page) {
  return page.evaluate(() => document.querySelector("header").getBoundingClientRect().top);
}

function shellGeometry(page) {
  return page.evaluate(() => {
    const d = document.documentElement;
    const root = document.getElementById("root");
    const main = document.getElementById("main-content");
    return {
      docScrollHeight: d.scrollHeight,
      docClientHeight: d.clientHeight,
      docScrollWidth: d.scrollWidth,
      docClientWidth: d.clientWidth,
      rootScrollHeight: root.scrollHeight,
      rootClientHeight: root.clientHeight,
      mainScrollHeight: main.scrollHeight,
      mainClientHeight: main.clientHeight,
      headerTop: document.querySelector("header").getBoundingClientRect().top,
      footerTop: document.querySelector("#root > div > section > footer").getBoundingClientRect().top,
    };
  });
}

const FINDINGS_LIST = '[role="listbox"][aria-label="Findings"]';
const SELECTED_ROW = `${FINDINGS_LIST} [role="option"][aria-selected="true"]`;
const DETAIL_HEADING = 'section[aria-label="Finding detail"] h2';
const PAGINATION_STATUS = 'nav[aria-label="Pagination for findings"] [role="status"]';

test("long finding lists stay in the single workspace scroll; keyboard, reveal and pagination keep content in view", async ({ page, backend }) => {
  test.setTimeout(300_000);
  await page.setViewportSize({ width: 1440, height: 900 });
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(String(error)));

  await connectThroughGate(page, backend);
  await skipReadinessWizard(page);

  // The document and #root stay viewport-sized on the dashboard: no document
  // scrollbars of their own, no horizontal document overflow.
  const dashboardShell = await shellGeometry(page);
  expect(dashboardShell.docScrollWidth).toBeLessThanOrEqual(dashboardShell.docClientWidth + 1);
  expect(dashboardShell.docScrollHeight).toBeLessThanOrEqual(dashboardShell.docClientHeight + 1);
  expect(dashboardShell.rootScrollHeight).toBeLessThanOrEqual(dashboardShell.rootClientHeight + 1);

  const project = await materializeEvalFixture(backend, FINDING_COUNT);
  await page.getByRole("button", { name: "Source Scan", exact: true }).click();
  await page.getByLabel("Project folder path").fill(project);
  await page.getByRole("button", { name: "Run scan", exact: true }).click();

  const listbox = page.locator(FINDINGS_LIST);
  // Reopen saved results so keyboard and pagination checks use server pages,
  // independently of the full finding array returned by a fresh scan.
  await expect(listbox.getByRole("option").first()).toBeVisible({ timeout: 120_000 });
  await expect(page.locator(PAGINATION_STATUS)).toContainText(`of ${FINDING_COUNT}`);

  await page.getByRole("button", { name: "Dashboard", exact: true }).click();
  const home = page.locator('section[aria-label="Project home"]');
  await home.getByLabel("Project folder").fill(project);
  await home.getByRole("button", { name: "Open project" }).click();
  await home.getByRole("button", { name: "Source results" }).click();

  // The saved run is now reopened through persisted paging; only the current
  // server page is held, and its pagination reports the full page count.
  await expect(listbox.getByRole("option").first()).toBeVisible({ timeout: 120_000 });
  await expect(page.locator(PAGINATION_STATUS)).toContainText(`of ${FINDING_COUNT}`);
  const pageSize = await listbox.getByRole("option").count();
  expect(pageSize).toBeLessThan(FINDING_COUNT);
  const pageCount = Math.ceil(FINDING_COUNT / pageSize);

  // The tall results page is the only thing that scrolls: the document and
  // #root stay fixed, and scrolling the workspace never moves header/status.
  const before = await shellGeometry(page);
  await page.evaluate(() => {
    const main = document.getElementById("main-content");
    main.scrollTop = main.scrollHeight;
  });
  const after = await shellGeometry(page);
  expect(after.mainScrollHeight).toBeGreaterThan(after.mainClientHeight);
  expect(after.docScrollWidth).toBeLessThanOrEqual(after.docClientWidth + 1);
  expect(after.docScrollHeight).toBeLessThanOrEqual(after.docClientHeight + 1);
  expect(after.rootScrollHeight).toBeLessThanOrEqual(after.rootClientHeight + 1);
  expect(after.headerTop).toBeCloseTo(before.headerTop, 1);
  expect(after.footerTop).toBeCloseTo(before.footerTop, 1);

  // The finding list grows into the workspace scroll: it has no vertical
  // scrollbar of its own, and its pagination is reachable at the bottom.
  const listGeom = await page.evaluate(() => {
    const el = document.querySelector('[role="listbox"][aria-label="Findings"]');
    return { scrollHeight: el.scrollHeight, clientHeight: el.clientHeight };
  });
  expect(listGeom.scrollHeight).toBeLessThanOrEqual(listGeom.clientHeight + 1);
  // No element inside the results panel may own a vertical scrollbar; the
  // list flows into the single workspace scroll.
  const nestedScrolls = await page.evaluate(() => {
    const scope = document.querySelector('section[aria-label="Source scan results"]');
    const found = [];
    for (const el of scope.querySelectorAll("*")) {
      const cs = getComputedStyle(el);
      if ((cs.overflowY === "auto" || cs.overflowY === "scroll") && el.scrollHeight > el.clientHeight + 1) {
        found.push({ tag: el.tagName, id: el.id, aria: el.getAttribute("aria-label") || "" });
      }
    }
    return found;
  });
  expect(nestedScrolls).toEqual([]);
  await expect(page.locator('nav[aria-label="Pagination for findings"]')).toBeInViewport();

  // Keyboard navigation selects rows and keeps them visible without moving
  // focus away from the listbox.
  await page.evaluate(() => {
    document.getElementById("main-content").scrollTop = 0;
  });
  await listbox.focus();
  await page.keyboard.press("End");
  await expect(page.locator(SELECTED_ROW)).toHaveAttribute("aria-posinset", String(pageSize));
  await expect(page.locator(SELECTED_ROW)).toBeVisible();
  await expect.poll(async () => (await inMainView(page, SELECTED_ROW)).inView).toBe(true);
  await expect(listbox).toBeFocused();
  await page.keyboard.press("Home");
  await expect(page.locator(SELECTED_ROW)).toHaveAttribute("aria-posinset", "1");
  await expect.poll(async () => (await inMainView(page, SELECTED_ROW)).inView).toBe(true);
  await expect(listbox).toBeFocused();
  const keyboardPosition = Math.min(31, pageSize);
  for (let i = 1; i < keyboardPosition; i++) await page.keyboard.press("ArrowDown");
  await expect(page.locator(SELECTED_ROW)).toHaveAttribute("aria-posinset", String(keyboardPosition));
  await expect.poll(async () => (await inMainView(page, SELECTED_ROW)).inView).toBe(true);
  await expect(listbox).toBeFocused();

  // Enter on the listbox reveals the offscreen detail heading and keeps focus.
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "eval() usage", level: 2 })).toBeVisible();
  await expect.poll(async () => (await inMainView(page, DETAIL_HEADING)).inView).toBe(true);
  await expect(listbox).toBeFocused();
  // Revealing the detail must not scroll the document/header out of place.
  expect(await headerTop(page)).toBeCloseTo(0, 1);

  // Clicking a lower row renders its detail in view (no update above the
  // viewport).
  await page.evaluate(() => {
    const main = document.getElementById("main-content");
    main.scrollTop = main.scrollHeight;
  });
  await listbox.getByRole("option").nth(pageSize - 1).getByRole("button").click();
  await expect(page.locator(SELECTED_ROW)).toHaveAttribute("aria-posinset", String(pageSize));
  await expect(page.getByRole("heading", { name: "eval() usage", level: 2 })).toBeVisible();
  await expect.poll(async () => (await inMainView(page, DETAIL_HEADING)).inView).toBe(true);
  expect(await headerTop(page)).toBeCloseTo(0, 1);

  // Paging forward returns the reader to the beginning of the results.
  await expect(page.locator(PAGINATION_STATUS)).toContainText(`Page 1 of ${pageCount}`);
  await page.getByRole("button", { name: "Next page of findings" }).click();
  await expect(page.locator(PAGINATION_STATUS)).toContainText(`Page 2 of ${pageCount}`);
  await expect.poll(async () => {
    const first = await inMainView(page, `${FINDINGS_LIST} [role="option"][aria-posinset="${pageSize + 1}"]`);
    return first.found && first.inView && first.top < first.mainTop + 60;
  }).toBe(true);
  const pagedShell = await shellGeometry(page);
  expect(pagedShell.headerTop).toBeCloseTo(0, 1);
  expect(pagedShell.footerTop).toBeCloseTo(before.footerTop, 1);

  // A different tool must not inherit the long results' scroll offset.
  await page.getByRole("button", { name: "Dashboard", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeInViewport();
  await expect.poll(() => page.locator("#main-content").evaluate(el => el.scrollTop)).toBe(0);

  expect(pageErrors).toEqual([]);
});

test("navigation boundary: 900px show/hide control, nothing clipped at 700px, and the 899px drawer", async ({ page, backend }) => {
  test.setTimeout(120_000);
  await connectThroughGate(page, backend);
  await skipReadinessWizard(page);

  await page.setViewportSize({ width: 900, height: 700 });
  const aside = page.locator('aside[aria-label="Primary navigation"]');
  // At exactly 900px the sidebar is in-flow at full width, with the
  // show/hide control in the header.
  const toggle = page.locator("header").getByRole("button", { name: "Collapse navigation" });
  await expect(toggle).toBeVisible();
  await expect(page.locator("#navigation-menu-button")).toBeHidden();
  expect((await aside.boundingBox()).width).toBeGreaterThan(200);

  // Nothing in the sidebar is cut off at 700px: the brand, project actions and
  // every tool live in one scroll region that ends above the pinned footer,
  // so each item can be scrolled fully into view, and the footer (Settings,
  // search hint, version) is entirely on screen.
  const sidebarFit = await page.evaluate(() => {
    const sidebar = document.querySelector('aside[aria-label="Primary navigation"]');
    const scroller = sidebar.querySelector("[data-sidebar-scroll]");
    const footer = scroller.nextElementSibling;
    const s = scroller.getBoundingClientRect();
    const f = footer.getBoundingClientRect();
    const unreachable = [];
    for (const button of scroller.querySelectorAll("button")) {
      const r = button.getBoundingClientRect();
      const top = r.top - s.top + scroller.scrollTop;
      if (top < 0 || top + r.height > scroller.scrollHeight + 1) unreachable.push(button.textContent);
    }
    scroller.scrollTop = scroller.scrollHeight;
    const buttons = scroller.querySelectorAll("button");
    const last = buttons[buttons.length - 1].getBoundingClientRect();
    const afterScroll = scroller.getBoundingClientRect();
    return {
      unreachable,
      scrolls: scroller.scrollHeight > scroller.clientHeight,
      lastName: buttons[buttons.length - 1].textContent,
      lastVisible: last.top >= afterScroll.top - 1 && last.bottom <= afterScroll.bottom + 1,
      scrollerEndsAboveFooter: s.bottom <= f.top + 1,
      footerOnScreen: f.top >= 0 && f.bottom <= window.innerHeight + 1,
      sidebarFits: sidebar.getBoundingClientRect().bottom <= window.innerHeight + 1,
    };
  });
  expect(sidebarFit.scrolls).toBe(true);
  expect(sidebarFit.unreachable).toEqual([]);
  expect(sidebarFit.lastName).toBe("Quality Lab");
  expect(sidebarFit.lastVisible).toBe(true);
  expect(sidebarFit.scrollerEndsAboveFooter).toBe(true);
  expect(sidebarFit.footerOnScreen).toBe(true);
  expect(sidebarFit.sidebarFits).toBe(true);
  await expect(aside.getByRole("button", { name: "Settings", exact: true })).toBeInViewport();
  await expect(aside.getByRole("button", { name: "Search tools and projects" })).toBeInViewport();

  // Hiding removes the whole sidebar (there is no icon rail); showing restores it.
  await toggle.click();
  await expect(page.getByRole("button", { name: "Expand navigation" })).toBeVisible();
  await expect(aside).toBeHidden();
  await page.getByRole("button", { name: "Expand navigation" }).click();
  await expect(page.getByRole("button", { name: "Collapse navigation" })).toBeVisible();
  await expect.poll(async () => (await aside.boundingBox()).width).toBeGreaterThan(200);

  // The Assistant no longer forces the sidebar narrow; hiding it there still
  // keeps the document within the viewport.
  await page.getByRole("button", { name: "AI Assistant", exact: true }).click();
  await expect(page.locator("#assistant-composer")).toBeVisible();
  expect((await aside.boundingBox()).width).toBeGreaterThan(200);
  await page.getByRole("button", { name: "Collapse navigation" }).click();
  await expect(aside).toBeHidden();
  await expect(page.locator("#assistant-composer")).toBeVisible();
  const hiddenShell = await shellGeometry(page);
  expect(hiddenShell.docScrollHeight).toBeLessThanOrEqual(hiddenShell.docClientHeight + 1);
  expect(hiddenShell.docScrollWidth).toBeLessThanOrEqual(hiddenShell.docClientWidth + 1);
  expect(hiddenShell.rootScrollHeight).toBeLessThanOrEqual(hiddenShell.rootClientHeight + 1);
  expect(hiddenShell.headerTop).toBeCloseTo(0, 1);

  // The choice survives a reload.
  await page.reload();
  await expect(page.getByRole("button", { name: "Expand navigation" })).toBeVisible();
  await expect(aside).toBeHidden();

  // Below 900px the sidebar is a drawer whatever the desktop preference;
  // Escape closes it and restores focus to the opener.
  await page.setViewportSize({ width: 899, height: 700 });
  await expect(page.locator("#navigation-menu-button")).toBeVisible();
  await expect(aside).toBeHidden();
  await page.locator("#navigation-menu-button").click();
  await expect(aside).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(aside).toBeHidden();
  await expect(page.locator("#navigation-menu-button")).toBeFocused();
});

test("Settings swaps the navigation for its sections, Back restores it, and nothing scrolls the document", async ({ page, backend }) => {
  test.setTimeout(120_000);
  await connectThroughGate(page, backend);
  await skipReadinessWizard(page);
  const aside = page.locator('aside[aria-label="Primary navigation"]');
  const documentFits = () =>
    page.evaluate(() => {
      const root = document.documentElement;
      const rootEl = document.getElementById("root");
      return {
        docY: root.scrollHeight - root.clientHeight,
        docX: root.scrollWidth - root.clientWidth,
        rootY: rootEl.scrollHeight - rootEl.clientHeight,
      };
    });

  for (const [width, height] of [[1440, 900], [899, 700]]) {
    await page.setViewportSize({ width, height });
    const drawer = width < 900;
    const openDrawer = async () => {
      if (!drawer) return;
      await page.locator("#navigation-menu-button").click();
      await expect(aside).toBeVisible();
    };

    await openDrawer();
    await aside.getByRole("button", { name: "Settings", exact: true }).click();
    // The main navigation is replaced, not extended.
    await openDrawer();
    const sections = aside.getByRole("navigation", { name: "Settings sections" });
    await expect(sections).toBeVisible();
    await expect(aside.getByRole("button", { name: "Back", exact: true })).toBeVisible();
    await expect(aside.getByRole("button", { name: "Source Scan", exact: true })).toHaveCount(0);
    // Settings reopens on the section last viewed (General on the first visit).
    await expect(sections.locator('button[aria-current="true"]')).toHaveCount(1);
    await expect(page.locator("header").getByRole("button", { name: "Save", exact: true })).toBeVisible();
    await expect(page.locator("header").getByRole("button", { name: "Reset", exact: true })).toBeVisible();

    // Every section fits the viewport without a document scrollbar.
    for (const title of ["General", "AI", "Scan defaults", "Live scanning", "Data sources", "Binary scanner", "Diagnostics", "About"]) {
      if (drawer && !(await aside.isVisible())) await openDrawer();
      await sections.getByRole("button", { name: title, exact: true }).click();
      await expect(page.locator("header").getByRole("heading", { level: 1, name: title })).toBeVisible();
      // The drawer closes on choosing a section; the in-flow sidebar stays.
      if (!drawer) await expect(sections.getByRole("button", { name: title, exact: true })).toHaveAttribute("aria-current", "true");
      const fit = await documentFits();
      expect(fit.docY, `${title} document height at ${width}x${height}`).toBeLessThanOrEqual(1);
      expect(fit.docX, `${title} document width at ${width}x${height}`).toBeLessThanOrEqual(1);
      expect(fit.rootY, `${title} root height at ${width}x${height}`).toBeLessThanOrEqual(1);
    }

    if (drawer && !(await aside.isVisible())) await openDrawer();
    await aside.getByRole("button", { name: "Back", exact: true }).click();
    await openDrawer();
    await expect(aside.getByRole("button", { name: "Dashboard", exact: true })).toBeVisible();
    await expect(aside.getByRole("navigation", { name: "Settings sections" })).toHaveCount(0);
    if (drawer) await page.keyboard.press("Escape");
  }
});
