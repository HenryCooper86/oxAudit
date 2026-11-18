import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Activity } from "lucide-react";
import { useMemo, useState } from "react";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../../lib/api";
import { useHeaderActions } from "../../lib/headerActions";
import {
  LEGACY_NAVIGATION_COLLAPSED_CACHE_KEY,
  NAVIGATION_HIDDEN_CACHE_KEY,
} from "../../lib/navigationPreference";
import { useAppStore } from "../../lib/stores";
import { useScanWorkStore } from "../../features/project-home/coordinator";
import { AppShell } from "./AppShell";

const platform = vi.hoisted(() => ({ macDesktop: false }));
vi.mock("../../lib/platform", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../lib/platform")>()),
  isMacDesktopHost: () => platform.macDesktop,
}));

beforeEach(() => {
  localStorage.clear();
  platform.macDesktop = false;
  useAppStore.setState({ page: "binary-scan", settings: null });
  useScanWorkStore.setState({ active: null, recoveryError: null });
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([]);
});

function renderShell(children: React.ReactNode = <button>Workspace action</button>, onOpenCommands = vi.fn()) {
  render(<AppShell onOpenCommands={onOpenCommands}>{children}</AppShell>);
  return { onOpenCommands };
}

function header() {
  return document.querySelector("header") as HTMLElement;
}

test("keyboard users can bypass navigation and continue into the current workspace", async () => {
  const user = userEvent.setup();
  renderShell();
  await user.tab();
  expect(screen.getByRole("link", { name: "Skip to workspace" })).toHaveFocus();
  await user.keyboard("{Enter}");
  expect(screen.getByRole("main")).toHaveFocus();
  await user.tab();
  expect(screen.getByRole("button", { name: "Workspace action" })).toHaveFocus();
});

test("Escape closes navigation and returns focus to its opener", async () => {
  const user = userEvent.setup();
  renderShell();
  const opener = screen.getByRole("button", { name: "Open navigation" });
  await user.click(opener);
  await waitFor(() => expect(screen.getAllByRole("button", { name: "Close navigation" })[1]).toHaveFocus());
  await user.keyboard("{Escape}");
  await waitFor(() => expect(opener).toHaveFocus());
  expect(screen.getAllByRole("button", { name: "Close navigation" })).toHaveLength(1);
  expect(screen.getByRole("main").parentElement).not.toHaveAttribute("inert");
});

test("the header toggle shows and hides the whole sidebar and remembers the choice", async () => {
  const user = userEvent.setup();
  const view = render(<AppShell onOpenCommands={vi.fn()}><button>Workspace action</button></AppShell>);
  const aside = screen.getByRole("complementary", { name: "Primary navigation" });
  const toggle = within(header()).getByRole("button", { name: "Collapse navigation" });
  expect(toggle).toHaveAttribute("aria-expanded", "true");
  expect(toggle).toHaveAttribute("aria-controls", aside.id);
  expect(aside.className).not.toMatch(/min-\[900px\]:hidden/);

  await user.click(toggle);
  const expand = within(header()).getByRole("button", { name: "Expand navigation" });
  expect(expand).toHaveAttribute("aria-expanded", "false");
  // Hidden outright at desktop widths: no icon rail remains.
  expect(aside.className).toMatch(/min-\[900px\]:hidden/);
  expect(aside.parentElement).toHaveAttribute("data-navigation", "hidden");
  expect(localStorage.getItem(NAVIGATION_HIDDEN_CACHE_KEY)).toBe("true");

  view.unmount();
  renderShell();
  expect(screen.getByRole("button", { name: "Expand navigation" })).toBeInTheDocument();
});

test("a stored icon-rail preference from the previous shell does not hide navigation", () => {
  localStorage.setItem(LEGACY_NAVIGATION_COLLAPSED_CACHE_KEY, "true");
  renderShell();
  expect(screen.getByRole("button", { name: "Collapse navigation" })).toHaveAttribute("aria-expanded", "true");
});

test("the Assistant page no longer forces the sidebar closed", () => {
  useAppStore.setState({ page: "assistant" });
  renderShell();
  expect(screen.getByRole("button", { name: "Collapse navigation" })).toHaveAttribute("aria-expanded", "true");
});

test("blocked browser storage leaves navigation usable for the current session", async () => {
  vi.spyOn(window, "localStorage", "get").mockImplementation(() => {
    throw new DOMException("Storage blocked", "SecurityError");
  });
  const user = userEvent.setup();
  renderShell();

  await user.click(screen.getByRole("button", { name: "Collapse navigation" }));
  expect(screen.getByRole("button", { name: "Expand navigation" })).toHaveAttribute("aria-expanded", "false");
  await user.click(screen.getByRole("button", { name: "Expand navigation" }));
  expect(screen.getByRole("button", { name: "Collapse navigation" })).toHaveAttribute("aria-expanded", "true");
  expect(screen.getByRole("button", { name: "Workspace action" })).toBeInTheDocument();
});

test("the header names the current page with its icon, without a brand, breadcrumb or search box", () => {
  renderShell();
  const shellHeader = header();
  expect(shellHeader).toHaveTextContent(/^Binary Scan$/);
  expect(shellHeader.querySelector("svg")).not.toBeNull();
  expect(within(shellHeader).queryByRole("button", { name: "Search tools and projects" })).not.toBeInTheDocument();
  // The page's ToolPage owns its h1; the header title is plain text.
  expect(within(shellHeader).queryByRole("heading")).not.toBeInTheDocument();
  expect(shellHeader).toHaveAttribute("data-tauri-drag-region");
});

test("pages without a ToolPage get their single h1 from the header", () => {
  useAppStore.setState({ page: "assistant" });
  renderShell();
  expect(within(header()).getByRole("heading", { level: 1, name: "AI Assistant" })).toBeInTheDocument();
});

test("the sidebar's search hint opens the command palette", async () => {
  const user = userEvent.setup();
  const { onOpenCommands } = renderShell();
  await user.click(screen.getByRole("button", { name: "Search tools and projects" }));
  expect(onOpenCommands).toHaveBeenCalledTimes(1);
});

function ActivityToggle() {
  const [open, setOpen] = useState(false);
  const actions = useMemo(
    () => [{ id: "activity", label: "Activity panel", icon: Activity, pressed: open, controls: "activity", onSelect: () => setOpen((value) => !value) }],
    [open],
  );
  useHeaderActions("test-page", actions);
  return <p>{open ? "Activity open" : "Activity closed"}</p>;
}

test("pages register header toggles that follow their state and leave with the page", async () => {
  const user = userEvent.setup();
  function Harness() {
    const [mounted, setMounted] = useState(true);
    return (
      <>
        {mounted && <ActivityToggle />}
        <button onClick={() => setMounted(false)}>Leave page</button>
      </>
    );
  }
  renderShell(<Harness />);
  const toggle = await within(header()).findByRole("button", { name: "Activity panel" });
  expect(toggle).toHaveAttribute("aria-pressed", "false");
  expect(toggle).toHaveAttribute("aria-controls", "activity");
  await user.click(toggle);
  expect(screen.getByText("Activity open")).toBeInTheDocument();
  expect(within(header()).getByRole("button", { name: "Activity panel" })).toHaveAttribute("aria-pressed", "true");
  await user.click(screen.getByRole("button", { name: "Leave page" }));
  await waitFor(() =>
    expect(within(header()).queryByRole("button", { name: "Activity panel" })).not.toBeInTheDocument(),
  );
});

test("on the macOS desktop a hidden sidebar leaves room for the traffic lights", async () => {
  platform.macDesktop = true;
  const user = userEvent.setup();
  renderShell();
  expect(header().className).not.toMatch(/pl-\[78px\]/);
  await user.click(screen.getByRole("button", { name: "Collapse navigation" }));
  expect(header().className).toMatch(/pl-\[78px\]/);
});

test("elsewhere a hidden sidebar keeps the ordinary header padding", async () => {
  const user = userEvent.setup();
  renderShell();
  await user.click(screen.getByRole("button", { name: "Collapse navigation" }));
  expect(header().className).not.toMatch(/pl-\[78px\]/);
});
