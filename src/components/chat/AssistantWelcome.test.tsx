import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";

const dialog = vi.hoisted(() => ({ open: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => dialog);
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn(() => new Promise(() => {})) }));

import { api } from "../../lib/api";
import { useToastStore } from "../../lib/stores";
import type { RecentProject } from "../../lib/types";
import { ASSISTANT_SUGGESTIONS, AssistantWelcome, projectName } from "./AssistantWelcome";

function recent(path: string): RecentProject {
  return {
    projectId: path,
    canonicalPath: path,
    displayName: projectName(path),
    lastOpenedAt: "2026-10-02T00:00:00Z",
    lastCompletedRunId: null,
    lastCompletedAt: null,
    openFindings: 0,
  } as RecentProject;
}

beforeEach(() => {
  dialog.open.mockReset();
  useToastStore.setState({ toasts: [] });
  vi.spyOn(api, "listSourceProjects").mockResolvedValue([recent("/work/payments"), recent("C:\\src\\web")]);
});

function setup(props: Partial<Parameters<typeof AssistantWelcome>[0]> = {}) {
  const onSelectProject = vi.fn();
  const onSuggestion = vi.fn();
  const user = userEvent.setup();
  render(
    <AssistantWelcome
      projectPath={null}
      onSelectProject={onSelectProject}
      projectDisabled={false}
      serverMode={false}
      onSuggestion={onSuggestion}
      {...props}
    />,
  );
  return { onSelectProject, onSuggestion, user };
}

test("welcomes with the title, what the assistant does, and starter chips that only report their prompt", async () => {
  const { onSuggestion, user } = setup();
  expect(screen.getByRole("heading", { name: "Welcome to oxAudit" })).toBeInTheDocument();
  expect(screen.getByText(/asks before using any other tool/)).toBeInTheDocument();
  expect(screen.getByText("What would you like to audit?")).toBeInTheDocument();
  for (const { label } of ASSISTANT_SUGGESTIONS) {
    expect(screen.getByRole("button", { name: label })).toBeEnabled();
  }
  await user.click(screen.getByRole("button", { name: "Compare XSS variants" }));
  expect(onSuggestion).toHaveBeenCalledWith(ASSISTANT_SUGGESTIONS[0].prompt);
});

test("the selector lists recent projects from the sidebar's source and reports the choice", async () => {
  const { onSelectProject, user } = setup();
  const trigger = screen.getByRole("button", { name: "Project for this conversation: No project" });
  await user.click(trigger);
  expect(trigger).toHaveAttribute("aria-expanded", "true");
  const list = screen.getByRole("listbox", { name: "Choose a project" });
  await within(list).findByRole("option", { name: "payments" });
  expect(api.listSourceProjects).toHaveBeenCalledWith(8);
  // Windows paths name their last segment too.
  expect(within(list).getByRole("option", { name: "web" })).toBeInTheDocument();
  // Without a project there is nothing to clear.
  expect(within(list).queryByRole("option", { name: "No project" })).not.toBeInTheDocument();
  await user.click(within(list).getByRole("option", { name: "payments" }));
  expect(onSelectProject).toHaveBeenCalledWith("/work/payments");
  expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
  expect(trigger).toHaveFocus();
});

test("the current project is marked, can be cleared, and choosing it again changes nothing", async () => {
  const { onSelectProject, user } = setup({ projectPath: "/work/payments" });
  await user.click(screen.getByRole("button", { name: "Project for this conversation: payments" }));
  const list = screen.getByRole("listbox", { name: "Choose a project" });
  const current = await within(list).findByRole("option", { name: "payments" });
  expect(current).toHaveAttribute("aria-selected", "true");
  await waitFor(() => expect(current).toHaveFocus());
  await user.click(current);
  expect(onSelectProject).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: /Project for this conversation/ }));
  await user.click(screen.getByRole("option", { name: "No project" }));
  expect(onSelectProject).toHaveBeenCalledWith(null);
});

test("arrow keys move through the options and Escape closes the list", async () => {
  const { user } = setup();
  const trigger = screen.getByRole("button", { name: /Project for this conversation/ });
  trigger.focus();
  await user.keyboard("{ArrowDown}");
  const first = await screen.findByRole("option", { name: "payments" });
  await waitFor(() => expect(first).toHaveFocus());
  await user.keyboard("{ArrowDown}");
  expect(screen.getByRole("option", { name: "web" })).toHaveFocus();
  await user.keyboard("{End}");
  expect(screen.getByRole("option", { name: "Browse for project…" })).toHaveFocus();
  await user.keyboard("{Home}");
  expect(first).toHaveFocus();
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
  expect(trigger).toHaveFocus();
});

test("on the desktop, Browse opens the native folder picker", async () => {
  dialog.open.mockResolvedValue("/home/me/new-repo");
  const { onSelectProject, user } = setup();
  await user.click(screen.getByRole("button", { name: /Project for this conversation/ }));
  await user.click(screen.getByRole("option", { name: "Browse for project…" }));
  expect(dialog.open).toHaveBeenCalledWith(expect.objectContaining({ directory: true, multiple: false }));
  await waitFor(() => expect(onSelectProject).toHaveBeenCalledWith("/home/me/new-repo"));
});

test("a cancelled picker changes nothing and a broken one says so", async () => {
  dialog.open.mockResolvedValueOnce(null).mockRejectedValueOnce(new Error("portal missing"));
  const { onSelectProject, user } = setup();
  await user.click(screen.getByRole("button", { name: /Project for this conversation/ }));
  await user.click(screen.getByRole("option", { name: "Browse for project…" }));
  await user.click(screen.getByRole("button", { name: /Project for this conversation/ }));
  await user.click(screen.getByRole("option", { name: "Browse for project…" }));
  await waitFor(() =>
    expect(useToastStore.getState().toasts.map((toast) => toast.message)).toEqual([
      "Could not open the folder picker. portal missing",
    ]),
  );
  expect(onSelectProject).not.toHaveBeenCalled();
});

test("in server mode there is no native picker: a server path is typed instead", async () => {
  const { onSelectProject, user } = setup({ serverMode: true });
  await user.click(screen.getByRole("button", { name: /Project for this conversation/ }));
  expect(screen.queryByRole("option", { name: "Browse for project…" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("option", { name: "Type a server path…" }));
  const field = screen.getByRole("textbox", { name: "Project folder on the server" });
  await waitFor(() => expect(field).toHaveFocus());
  expect(screen.getByText("Paths refer to the server's filesystem.")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Use folder" })).toBeDisabled();
  await user.type(field, " /srv/repos/app {Enter}");
  expect(onSelectProject).toHaveBeenCalledWith("/srv/repos/app");
  expect(dialog.open).not.toHaveBeenCalled();
});

test("recent projects that cannot be listed are explained, and the selector can be disabled", async () => {
  vi.mocked(api.listSourceProjects).mockRejectedValue(new Error("db locked"));
  const { user } = setup();
  await user.click(screen.getByRole("button", { name: /Project for this conversation/ }));
  expect(await screen.findByText("Recent projects are unavailable.")).toBeInTheDocument();
});

test("a disabled selector cannot open", () => {
  setup({ projectDisabled: true });
  expect(screen.getByRole("button", { name: /Project for this conversation/ })).toBeDisabled();
});
