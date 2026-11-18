import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { version } from "../../package.json";
import { api } from "../lib/api";
import { useAppStore, useToastStore } from "../lib/stores";
import type { RecentProject } from "../lib/types";
import { Sidebar, SIDEBAR_RECENT_LIMIT } from "./Sidebar";

const environment = vi.hoisted(() => ({ server: false, open: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: environment.open }));
vi.mock("../lib/transport", () => ({
  get serverMode() {
    return environment.server;
  },
  httpInvoke: vi.fn(),
}));

function project(index: number): RecentProject {
  return {
    projectId: `p${index}`,
    canonicalPath: `/work/project-${index}`,
    displayName: `project-${index}`,
    lastOpenedAt: "2026-11-18T00:00:00Z",
    lastCompletedRunId: null,
    lastCompletedAt: null,
    openFindings: 0,
    critical: 0,
    high: 0,
  };
}

beforeEach(() => {
  environment.server = false;
  environment.open.mockReset();
  useAppStore.setState({
    page: "dashboard",
    activeProject: null,
    selectedProject: null,
    projectFieldRequest: null,
  });
  useToastStore.setState({ toasts: [] });
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([]);
});

function renderSidebar(overrides: Partial<Parameters<typeof Sidebar>[0]> = {}) {
  const props = { open: true, onClose: vi.fn(), onOpenCommands: vi.fn(), ...overrides };
  render(<Sidebar {...props} />);
  return props;
}

function navigation() {
  return screen.getByRole("complementary", { name: "Primary navigation" });
}

test("YARA Scan and Template Scan are in the Scanning group and navigate", async () => {
  const { onClose } = renderSidebar();
  await userEvent.click(screen.getByRole("button", { name: "YARA Scan" }));
  expect(useAppStore.getState().page).toBe("yara-scan");
  await userEvent.click(screen.getByRole("button", { name: "Template Scan" }));
  expect(useAppStore.getState().page).toBe("template-scan");
  expect(onClose).toHaveBeenCalledTimes(2);
});

test("groups read like oxFuzz: a short workspace group, then the pipeline, results, intelligence and quality", async () => {
  renderSidebar();
  const tools = screen.getByRole("navigation", { name: "Tools" });
  const labels = Array.from(tools.querySelectorAll("span.uppercase"), (label) => label.textContent);
  expect(labels).toEqual(["Workspace", "Scanning", "Results", "Intelligence", "Quality"]);
  const items = within(tools).getAllByRole("button").map((button) => button.textContent);
  expect(items.slice(0, 3)).toEqual(["Dashboard", "Portfolio", "AI Assistant"]);
  expect(items).toContain("Advisory Database");
  expect(items).not.toContain("Settings");
  // Settings is an ordinary item in the footer, after the tools.
  const settings = screen.getByRole("button", { name: "Settings" });
  expect(tools).not.toContainElement(settings);
  await waitFor(() => expect(api.listSourceProjects).toHaveBeenCalled());
});

test("the active page is marked current", async () => {
  useAppStore.setState({ page: "inventory" });
  renderSidebar();
  expect(screen.getByRole("button", { name: "Inventory" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("button", { name: "Dashboard" })).not.toHaveAttribute("aria-current");
  await waitFor(() => expect(api.listSourceProjects).toHaveBeenCalled());
});

test("recent projects are capped and switch the active project the way the command palette does", async () => {
  vi.mocked(api.listSourceProjects).mockResolvedValue(
    Array.from({ length: SIDEBAR_RECENT_LIMIT + 2 }, (_, index) => project(index)),
  );
  const { onClose } = renderSidebar();
  await screen.findByRole("button", { name: "project-0" });
  expect(screen.queryByRole("button", { name: `project-${SIDEBAR_RECENT_LIMIT}` })).not.toBeInTheDocument();
  const recent = screen.getAllByRole("button", { name: /^project-/ });
  expect(recent).toHaveLength(SIDEBAR_RECENT_LIMIT);
  expect(recent[1]).toHaveAttribute("title", "/work/project-1");

  await userEvent.click(recent[1]);
  expect(useAppStore.getState().activeProject).toBe("/work/project-1");
  expect(useAppStore.getState().page).toBe("source-scan");
  expect(onClose).toHaveBeenCalled();
  await waitFor(() => expect(screen.getByRole("button", { name: "project-1" })).toHaveAttribute("aria-current", "true"));
});

test("an empty recent list explains how to start", async () => {
  renderSidebar();
  expect(await screen.findByText(/No projects yet/)).toBeInTheDocument();
});

test("a recent-project load failure does not hide navigation", async () => {
  vi.mocked(api.listSourceProjects).mockRejectedValue(new Error("database locked"));
  renderSidebar();
  expect(await screen.findByText(/Recent projects unavailable/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Source Scan" })).toBeEnabled();
});

test("Open project on the desktop picks a folder and selects it as Project home does", async () => {
  environment.open.mockResolvedValue("/work/picked");
  useAppStore.setState({ page: "inventory" });
  const { onClose } = renderSidebar();
  await userEvent.click(screen.getByRole("button", { name: "Open project" }));
  await waitFor(() => expect(useAppStore.getState().selectedProject).toBe("/work/picked"));
  expect(environment.open).toHaveBeenCalledWith({ directory: true, multiple: false, title: "Open project" });
  expect(useAppStore.getState().page).toBe("dashboard");
  expect(onClose).toHaveBeenCalled();
});

test("cancelling the folder picker changes nothing", async () => {
  environment.open.mockResolvedValue(null);
  useAppStore.setState({ page: "inventory", selectedProject: "/kept" });
  renderSidebar();
  await userEvent.click(screen.getByRole("button", { name: "Open project" }));
  await waitFor(() => expect(environment.open).toHaveBeenCalled());
  expect(useAppStore.getState().selectedProject).toBe("/kept");
  expect(useAppStore.getState().page).toBe("inventory");
});

test("a folder picker failure is reported and falls back to the typed field", async () => {
  environment.open.mockRejectedValue(new Error("Dialog unavailable"));
  renderSidebar();
  await userEvent.click(screen.getByRole("button", { name: "Open project" }));
  await waitFor(() => expect(useToastStore.getState().toasts).toHaveLength(1));
  expect(useToastStore.getState().toasts[0]).toMatchObject({ kind: "error" });
  expect(useToastStore.getState().toasts[0].message).toMatch(/Dialog unavailable/);
  expect(useAppStore.getState().projectFieldRequest).not.toBeNull();
  expect(useAppStore.getState().page).toBe("dashboard");
});

test("in server mode Open project goes to the typed project field instead of a native picker", async () => {
  environment.server = true;
  useAppStore.setState({ page: "inventory" });
  renderSidebar();
  await userEvent.click(screen.getByRole("button", { name: "Open project" }));
  expect(environment.open).not.toHaveBeenCalled();
  expect(useAppStore.getState().page).toBe("dashboard");
  expect(useAppStore.getState().projectFieldRequest).toBe(1);
});

test("the footer search hint is a real button that opens the command palette", async () => {
  const { onOpenCommands } = renderSidebar();
  const search = screen.getByRole("button", { name: "Search tools and projects" });
  expect(search).toHaveAttribute("aria-haspopup", "dialog");
  expect(search).toHaveAttribute("aria-keyshortcuts", "Meta+K Control+K");
  expect(search).toHaveTextContent(/Press.*to search/);
  await userEvent.click(search);
  expect(onOpenCommands).toHaveBeenCalledTimes(1);
  expect(within(navigation()).getByText(`oxAudit v${version}`)).toBeInTheDocument();
});

test("the sidebar has a brand but no heading, header, footer or list items of its own", async () => {
  // The shell's first <header> and only <footer> belong to the workspace
  // column, the page's <h1> is its title, and the Portfolio smoke test counts
  // every listitem on the page.
  vi.mocked(api.listSourceProjects).mockResolvedValue([project(1)]);
  renderSidebar();
  await screen.findByRole("button", { name: "project-1" });
  const aside = navigation();
  expect(within(aside).getByText("oxAudit")).toBeInTheDocument();
  expect(within(aside).queryAllByRole("heading")).toHaveLength(0);
  expect(within(aside).queryAllByRole("listitem")).toHaveLength(0);
  expect(aside.querySelector("header, footer")).toBeNull();
});
