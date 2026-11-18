import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../lib/api";
import { useAppStore } from "../lib/stores";
import { SETTINGS_SECTIONS } from "../lib/settingsSections";
import { useScanWorkStore } from "../features/project-home/coordinator";
import { projectSettings } from "../../tests/fixtures/projectHome";
import { SettingsPage } from "../pages/SettingsPage";
import { Sidebar } from "./Sidebar";
import { AppShell } from "./workbench/AppShell";

beforeEach(() => {
  localStorage.clear();
  useAppStore.setState({
    page: "source-scan",
    settingsSection: "general",
    settingsReturnPage: "dashboard",
    settings: { ...projectSettings, theme: "dark" },
  });
  useScanWorkStore.setState({ active: null, recoveryError: null });
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([]);
  vi.spyOn(api, "getTotalUsage").mockRejectedValue("No usage");
});

function shell() {
  return render(
    <AppShell onOpenCommands={() => {}}>
      {useAppStore.getState().page === "settings" ? <SettingsPage /> : <p>Workspace</p>}
    </AppShell>,
  );
}

/** Re-render the shell for the current page, as App does. */
function Harness() {
  const page = useAppStore((state) => state.page);
  return (
    <AppShell onOpenCommands={() => {}}>{page === "settings" ? <SettingsPage /> : <p>Workspace</p>}</AppShell>
  );
}

const nav = () => screen.getByRole("complementary", { name: "Primary navigation" });
const header = () => document.querySelector("header") as HTMLElement;

test("Settings replaces the main navigation with a sub-navigation and Back restores it", async () => {
  const user = userEvent.setup();
  render(<Harness />);
  expect(within(nav()).getByRole("button", { name: "Source Scan" })).toHaveAttribute("aria-current", "page");
  await user.click(within(nav()).getByRole("button", { name: "Settings" }));

  expect(useAppStore.getState().page).toBe("settings");
  expect(within(nav()).queryByRole("button", { name: "Source Scan" })).not.toBeInTheDocument();
  expect(within(nav()).queryByRole("button", { name: "Open project" })).not.toBeInTheDocument();
  const sections = within(within(nav()).getByRole("navigation", { name: "Settings sections" })).getAllByRole("button");
  expect(sections.map((button) => button.textContent)).toEqual(SETTINGS_SECTIONS.map((section) => section.title));
  expect(within(nav()).getByRole("button", { name: "Back" })).toBeInTheDocument();
  // The brand row and the footer stay.
  expect(within(nav()).getByText("oxAudit")).toBeInTheDocument();
  expect(within(nav()).getByRole("button", { name: "Search tools and projects" })).toBeInTheDocument();

  await user.click(within(nav()).getByRole("button", { name: "Back" }));
  expect(useAppStore.getState().page).toBe("source-scan");
  expect(within(nav()).getByRole("button", { name: "Source Scan" })).toHaveAttribute("aria-current", "page");
  expect(within(nav()).queryByRole("navigation", { name: "Settings sections" })).not.toBeInTheDocument();
});

test("Back returns to whichever page Settings was opened from", async () => {
  const user = userEvent.setup();
  useAppStore.setState({ page: "yara-scan" });
  render(<Harness />);
  await user.click(within(nav()).getByRole("button", { name: "Settings" }));
  await user.click(within(nav()).getByRole("button", { name: "Back" }));
  expect(useAppStore.getState().page).toBe("yara-scan");
});

test("selecting a section marks it current, retitles the header and shows its groups", async () => {
  const user = userEvent.setup();
  useAppStore.getState().openSettings();
  render(<Harness />);
  const sections = within(nav()).getByRole("navigation", { name: "Settings sections" });
  expect(within(sections).getByRole("button", { name: "General" })).toHaveAttribute("aria-current", "true");
  expect(screen.getByRole("heading", { level: 1, name: "General" })).toBeInTheDocument();
  expect(screen.getByRole("region", { name: "Appearance" })).toBeInTheDocument();

  await user.click(within(sections).getByRole("button", { name: "AI" }));
  expect(within(sections).getByRole("button", { name: "AI" })).toHaveAttribute("aria-current", "true");
  expect(within(sections).getByRole("button", { name: "General" })).not.toHaveAttribute("aria-current");
  const title = screen.getByRole("heading", { level: 1, name: "AI" });
  expect(header()).toContainElement(title);
  expect(title.className).toContain("italic");
  expect(title.className).toContain("font-display");
  expect(screen.getByRole("region", { name: "AI Engine" })).toBeInTheDocument();
  expect(screen.queryByRole("region", { name: "Appearance" })).not.toBeInTheDocument();
});

test("the section buttons are in the tab order", async () => {
  const user = userEvent.setup();
  useAppStore.getState().openSettings();
  render(<Harness />);
  // Let any pending drawer focus restoration from a previous test settle.
  await act(async () => {
    await new Promise((resolve) => requestAnimationFrame(() => resolve(null)));
  });
  const back = within(nav()).getByRole("button", { name: "Back" });
  back.focus();
  await user.tab();
  expect(within(nav()).getByRole("button", { name: "General" })).toHaveFocus();
  await user.tab();
  expect(within(nav()).getByRole("button", { name: "AI" })).toHaveFocus();
  await user.keyboard("{Enter}");
  expect(useAppStore.getState().settingsSection).toBe("ai");
});

test("deep links open the relevant section", () => {
  useAppStore.setState({ page: "dashboard" });
  act(() => useAppStore.getState().openSettings("ai"));
  expect(useAppStore.getState()).toMatchObject({ page: "settings", settingsSection: "ai", settingsReturnPage: "dashboard" });
  render(<Harness />);
  expect(screen.getByRole("heading", { level: 1, name: "AI" })).toBeInTheDocument();
  // Opening again from inside Settings keeps the original way back.
  act(() => useAppStore.getState().openSettings("scan-defaults"));
  expect(useAppStore.getState().settingsReturnPage).toBe("dashboard");
  expect(screen.getByRole("heading", { level: 1, name: "Scan defaults" })).toBeInTheDocument();
});

test("a plain page change into Settings keeps the last section and remembers the way back", () => {
  useAppStore.setState({ page: "assistant", settingsSection: "data-sources" });
  act(() => useAppStore.getState().setPage("settings"));
  expect(useAppStore.getState()).toMatchObject({ page: "settings", settingsSection: "data-sources", settingsReturnPage: "assistant" });
});

test("Save and Reset sit in the shell header, on the right", () => {
  useAppStore.getState().openSettings();
  render(<Harness />);
  const bar = within(header());
  const save = bar.getByRole("button", { name: "Save" });
  const reset = bar.getByRole("button", { name: "Reset" });
  expect(save).toBeDisabled();
  expect(reset).toBeEnabled();
  const title = bar.getByRole("heading", { level: 1 });
  expect(title.compareDocumentPosition(reset) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(reset.compareDocumentPosition(save) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(within(screen.getByRole("main")).queryByRole("button", { name: "Save" })).not.toBeInTheDocument();
});

test("unsaved edits survive a section change, and leaving Settings discards them", async () => {
  const user = userEvent.setup();
  useAppStore.getState().openSettings();
  render(<Harness />);
  fireEvent.change(screen.getByLabelText("Preferred editor"), { target: { value: "vscode" } });
  expect(within(header()).getByText("Unsaved changes")).toBeInTheDocument();
  expect(within(header()).getByRole("button", { name: "Save" })).toBeEnabled();

  await user.click(within(nav()).getByRole("button", { name: "Scan defaults" }));
  expect(within(header()).getByText("Unsaved changes")).toBeInTheDocument();
  await user.click(within(nav()).getByRole("button", { name: "General" }));
  expect(screen.getByLabelText("Preferred editor")).toHaveValue("vscode");

  await user.click(within(nav()).getByRole("button", { name: "Back" }));
  expect(within(header()).queryByRole("button", { name: "Save" })).not.toBeInTheDocument();
  await act(async () => useAppStore.getState().openSettings());
  expect(await screen.findByLabelText("Preferred editor")).toHaveValue(projectSettings.editor ?? "system");
  expect(within(header()).getByRole("button", { name: "Save" })).toBeDisabled();
});

test("below 900px choosing a section or Back closes the drawer", async () => {
  const user = userEvent.setup();
  useAppStore.getState().openSettings();
  const onClose = vi.fn();
  render(<Sidebar open onClose={onClose} onOpenCommands={() => {}} />);
  await user.click(screen.getByRole("button", { name: "Live scanning" }));
  expect(useAppStore.getState().settingsSection).toBe("live-scanning");
  expect(onClose).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole("button", { name: "Back" }));
  expect(onClose).toHaveBeenCalledTimes(2);
  expect(useAppStore.getState().page).not.toBe("settings");
});

test("the drawer opens onto the settings sub-navigation and keeps its focus contract", async () => {
  const user = userEvent.setup();
  useAppStore.getState().openSettings();
  shell();
  const opener = screen.getByRole("button", { name: "Open navigation" });
  await user.click(opener);
  expect(within(nav()).getByRole("navigation", { name: "Settings sections" })).toBeInTheDocument();
  await user.keyboard("{Escape}");
  expect(screen.getAllByRole("button", { name: "Close navigation" })).toHaveLength(1);
});

test("settings rows keep their label and control associated, with the description as the control's description", () => {
  useAppStore.getState().openSettings("live-scanning");
  render(<Harness />);
  const rate = screen.getByLabelText("Requests per second");
  expect(rate.tagName).toBe("INPUT");
  const described = rate.getAttribute("aria-describedby") ?? "";
  expect(document.getElementById(described.split(" ")[0])).toHaveTextContent("Across the whole run, 1 to 1,000.");
  fireEvent.change(rate, { target: { value: "0" } });
  expect(rate).toHaveAttribute("aria-invalid", "true");
  expect(screen.getByRole("alert")).toHaveTextContent(/whole number between 1 and 1,000/);
  expect(rate.getAttribute("aria-describedby")).toContain("live-requests-per-second-error");
});
