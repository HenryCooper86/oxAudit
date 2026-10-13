import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../lib/api";
import { useAppStore } from "../lib/stores";
import { projectSettings } from "../../tests/fixtures/projectHome";
import type { SaveSettingsResult } from "../lib/types";
import { SettingsPage } from "./SettingsPage";

beforeEach(() => {
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
