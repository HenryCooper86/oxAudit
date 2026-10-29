import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../lib/api";
import { useAppStore } from "../lib/stores";
import { projectSettings } from "../../tests/fixtures/projectHome";
import type { SaveSettingsResult } from "../lib/types";
import { SettingsPage } from "./SettingsPage";

const transport = vi.hoisted(() => ({ serverMode: false }));
vi.mock("../lib/transport", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/transport")>();
  return {
    ...actual,
    get serverMode() {
      return transport.serverMode;
    },
  };
});

beforeEach(() => {
  transport.serverMode = false;
  useAppStore.setState({ settings: { ...projectSettings, theme: "dark" }, settingsLoadError: false });
  vi.spyOn(api, "getTotalUsage").mockRejectedValue("No usage");
});

test("changing theme during a pending full save keeps the theme controls aligned with saved settings", async () => {
  let resolve!: (value: SaveSettingsResult) => void;
  const pending = new Promise<SaveSettingsResult>(done => { resolve = done; });
  vi.spyOn(api, "saveSettings").mockReturnValueOnce(pending)
    .mockImplementation(async request => ({ settings: request.settings }));
  render(<SettingsPage />);
  fireEvent.change(screen.getByLabelText("Preferred editor"), { target: { value: "vscode" } });
  await userEvent.click(screen.getByRole("button", { name: "Save" }));
  await userEvent.click(screen.getByRole("radio", { name: "light" }));
  await act(async () => resolve({ settings: { ...projectSettings, editor: "vscode", theme: "dark" } }));
  await waitFor(() => expect(useAppStore.getState().settings?.theme).toBe("light"));
  expect(screen.getByRole("radio", { name: "light" })).toHaveAttribute("aria-checked", "true");
  expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
});

test("a failed automatic theme save restores the persisted preference and permits retry", async () => {
  vi.spyOn(api, "saveSettings").mockRejectedValueOnce("Disk unavailable")
    .mockImplementation(async request => ({ settings: request.settings }));
  render(<SettingsPage />);
  await userEvent.click(screen.getByRole("radio", { name: "light" }));
  await waitFor(() => expect(screen.getByRole("radio", { name: "dark" })).toHaveAttribute("aria-checked", "true"));
  await userEvent.click(screen.getByRole("radio", { name: "light" }));
  await waitFor(() => expect(useAppStore.getState().settings?.theme).toBe("light"));
});

test("a delayed theme save does not overwrite a newer reset draft", async () => {
  let resolve!: (value: SaveSettingsResult) => void;
  vi.spyOn(api, "saveSettings").mockReturnValue(new Promise(done => { resolve = done; }));
  render(<SettingsPage />);
  await userEvent.click(screen.getByRole("radio", { name: "light" }));
  await userEvent.click(screen.getByRole("button", { name: "Reset" }));
  await act(async () => resolve({ settings: { ...projectSettings, theme: "light" } }));
  expect(screen.getByRole("radio", { name: "dark" })).toHaveAttribute("aria-checked", "true");
  expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
});

const commandError = (message: string) => ({ code: "persistenceUnavailable", message, detail: null, retryable: true });

function saveRequests() {
  return vi.spyOn(api, "saveSettings").mockImplementation(async request => ({ settings: request.settings }));
}

test("list textareas keep newlines and trailing spaces while typing and save the parsed list", async () => {
  const save = saveRequests();
  render(<SettingsPage />);
  const hosts = screen.getByLabelText("Allowed fetch hosts") as HTMLTextAreaElement;
  await userEvent.clear(hosts);
  await userEvent.type(hosts, "psirt.vendor.example {Enter}  advisories.example ");
  expect(hosts.value).toBe("psirt.vendor.example \n  advisories.example ");

  const dirs = screen.getByLabelText("Ignored directories") as HTMLTextAreaElement;
  await userEvent.clear(dirs);
  await userEvent.type(dirs, "node_modules{Enter}{Enter}generated ");
  expect(dirs.value).toBe("node_modules\n\ngenerated ");

  await userEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(save).toHaveBeenCalled());
  const submitted = save.mock.calls[0][0].settings;
  expect(submitted.agentAllowedFetchHosts).toEqual(["psirt.vendor.example", "advisories.example"]);
  expect(submitted.scan.ignoredDirs).toEqual(["node_modules", "generated"]);
  await waitFor(() => expect(dirs.value).toBe("node_modules\ngenerated"));
});

test("reset repopulates list text being edited", async () => {
  render(<SettingsPage />);
  const dirs = screen.getByLabelText("Ignored directories") as HTMLTextAreaElement;
  await userEvent.clear(dirs);
  await userEvent.type(dirs, "only-this{Enter}");
  await userEvent.click(screen.getByRole("button", { name: "Reset" }));
  expect(dirs.value.split("\n")).toContain("node_modules");
  expect(dirs.value).not.toContain("only-this");
});

test("clearing a number field keeps it empty with an inline error and blocks save", async () => {
  const save = saveRequests();
  render(<SettingsPage />);
  const timeout = screen.getByLabelText("Timeout (seconds)") as HTMLInputElement;
  await userEvent.clear(timeout);
  expect(timeout.value).toBe("");
  expect(await screen.findByText(/whole number between 10 and 600/i)).toBeInTheDocument();
  expect(timeout).toHaveAttribute("aria-invalid", "true");
  expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();

  await userEvent.type(timeout, "300");
  expect(screen.queryByText(/whole number between 10 and 600/i)).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(save).toHaveBeenCalled());
  expect(save.mock.calls[0][0].settings.ai.timeoutSecs).toBe(300);
});

test.each([
  ["Max file size (KB)", "-5"],
  ["Max file size (KB)", "1.5"],
  ["Max tokens", "100"],
  ["Context window", "-1"],
])("%s rejects %s before it reaches the backend", async (label, value) => {
  const save = saveRequests();
  render(<SettingsPage />);
  const input = screen.getByLabelText(label) as HTMLInputElement;
  fireEvent.change(input, { target: { value } });
  fireEvent.blur(input);
  expect(input.value).toBe(value);
  expect(input).toHaveAttribute("aria-invalid", "true");
  expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  expect(save).not.toHaveBeenCalled();
});

test("structured errors show their message, not [object Object]", async () => {
  vi.spyOn(api, "saveSettings").mockRejectedValue(commandError("Settings file is read-only"));
  render(<SettingsPage />);
  fireEvent.change(screen.getByLabelText("Preferred editor"), { target: { value: "vscode" } });
  await userEvent.click(screen.getByRole("button", { name: "Save" }));
  expect(await screen.findByText("Settings file is read-only")).toBeInTheDocument();
  expect(screen.queryByText(/object Object/)).not.toBeInTheDocument();
});

test("a structured load failure shows its message", async () => {
  useAppStore.setState({ settings: null, settingsLoadError: true });
  vi.spyOn(api, "loadSettings").mockRejectedValue(commandError("Config database is locked"));
  render(<SettingsPage />);
  await userEvent.click(screen.getByRole("button", { name: "Retry" }));
  expect(await screen.findByText(/Config database is locked/)).toBeInTheDocument();
  expect(screen.queryByText(/object Object/)).not.toBeInTheDocument();
});

test("server mode replaces the AI section with a desktop-app note", () => {
  transport.serverMode = true;
  render(<SettingsPage />);
  expect(screen.queryByLabelText("Base URL")).not.toBeInTheDocument();
  expect(screen.queryByRole("switch", { name: "Enable AI engine" })).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Allowed fetch hosts")).not.toBeInTheDocument();
  expect(screen.getByText(/AI features are available in the oxAudit desktop app/i)).toBeInTheDocument();
  expect(screen.getByLabelText("Ignored directories")).toBeInTheDocument();
});
