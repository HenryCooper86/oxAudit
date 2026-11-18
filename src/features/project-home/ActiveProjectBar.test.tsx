import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { projectSettings, projectContext } from "../../../tests/fixtures/projectHome";
import { api } from "../../lib/api";
import { useAppStore } from "../../lib/stores";
import { Dashboard } from "../../pages/Dashboard";
import { useScanWorkStore } from "./coordinator";

const environment = vi.hoisted(() => ({ server: false, open: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: environment.open }));
vi.mock("../../lib/transport", () => ({
  get serverMode() {
    return environment.server;
  },
  httpInvoke: vi.fn(),
}));

beforeEach(() => {
  environment.server = false;
  environment.open.mockReset();
  useAppStore.setState({
    selectedProject: null,
    activeProject: null,
    projectHandoff: null,
    projectFieldRequest: null,
    page: "dashboard",
    settings: projectSettings,
  });
  useScanWorkStore.setState({ active: null, check: null });
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([]);
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([]);
  vi.spyOn(api, "listSourceRuns").mockResolvedValue([]);
  vi.spyOn(api, "inspectSourceProject").mockImplementation(async (path) => projectContext(path));
  vi.spyOn(api, "setActiveProject").mockResolvedValue();
});

test("with no project the Dashboard bar says so and opens the folder picker", async () => {
  environment.open.mockResolvedValue("/work/picked");
  render(<Dashboard />);
  const bar = screen.getByRole("region", { name: "Active project" });
  expect(bar).toHaveTextContent("No project selected");
  expect(bar).toHaveClass("border-l-accent");
  await userEvent.click(screen.getByRole("button", { name: "Open project…" }));
  await waitFor(() => expect(useAppStore.getState().selectedProject).toBe("/work/picked"));
  expect(await screen.findByText("/work/picked", { selector: "span" })).toBeInTheDocument();
  expect(screen.getByRole("region", { name: "Active project" })).toHaveClass("border-l-success");
  expect(screen.getByRole("button", { name: "Change project…" })).toBeInTheDocument();
});

test("the bar names the selected project by its folder and shows the full path", async () => {
  useAppStore.setState({ selectedProject: "/work/client-api" });
  render(<Dashboard />);
  const bar = screen.getByRole("region", { name: "Active project" });
  expect(bar).toHaveTextContent("client-api");
  expect(bar).toHaveTextContent("/work/client-api");
  await waitFor(() => expect(api.inspectSourceProject).toHaveBeenCalled());
});

test("in server mode the bar focuses Project home's typed folder field", async () => {
  environment.server = true;
  render(<Dashboard />);
  await userEvent.click(screen.getByRole("button", { name: "Enter server path" }));
  expect(environment.open).not.toHaveBeenCalled();
  await waitFor(() => expect(screen.getByRole("textbox", { name: "Project folder" })).toHaveFocus());
  expect(useAppStore.getState().projectFieldRequest).toBeNull();
});

test("a field request made before the Dashboard mounts is honoured once", async () => {
  useAppStore.getState().requestProjectField();
  const view = render(<Dashboard />);
  await waitFor(() => expect(screen.getByRole("textbox", { name: "Project folder" })).toHaveFocus());
  expect(useAppStore.getState().projectFieldRequest).toBeNull();
  view.unmount();
  render(<Dashboard />);
  expect(screen.getByRole("textbox", { name: "Project folder" })).not.toHaveFocus();
});
