import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { StrictMode, useState } from "react";
import { beforeEach, expect, test, vi } from "vitest";
import { FolderPicker } from "./FolderPicker";

const environment = vi.hoisted(() => ({ server: false, open: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: environment.open }));
vi.mock("../lib/transport", () => ({ get serverMode() { return environment.server; } }));

function Picker({ allowFiles = false }: { allowFiles?: boolean }) {
  const [path, setPath] = useState("/retained");
  return <FolderPicker value={path} onChange={setPath} inputLabel="Scan target path" allowFiles={allowFiles} />;
}

beforeEach(() => { environment.server = false; environment.open.mockReset(); });

test("folder and file actions state their picker mode and a cancelled dialog preserves the target", async () => {
  environment.open.mockResolvedValue(null);
  render(<Picker allowFiles />);
  fireEvent.click(screen.getByRole("button", { name: "Choose file…" }));
  await waitFor(() => expect(environment.open).toHaveBeenCalledWith({ directory: false, multiple: false, title: "Select a file" }));
  expect(screen.getByRole("textbox", { name: "Scan target path" })).toHaveValue("/retained");
  fireEvent.click(screen.getByRole("button", { name: "Choose folder…" }));
  await waitFor(() => expect(environment.open).toHaveBeenLastCalledWith({ directory: true, multiple: false, title: "Select a folder" }));
});

test("a picker failure is announced and associated with the target input", async () => {
  environment.open.mockRejectedValue(new Error("Dialog unavailable"));
  render(<Picker />);
  fireEvent.click(screen.getByRole("button", { name: "Choose folder…" }));
  const error = await screen.findByRole("alert");
  expect(error).toHaveTextContent(/Dialog unavailable/);
  expect(screen.getByRole("textbox", { name: "Scan target path" })).toHaveAttribute("aria-describedby", expect.stringContaining(error.id));
  expect(screen.getByRole("textbox", { name: "Scan target path" })).toHaveValue("/retained");
});

test("browser targets explain the server filesystem and offer no native picker", () => {
  environment.server = true;
  render(<Picker allowFiles />);
  expect(screen.getByRole("textbox", { name: "Scan target path" })).toHaveAccessibleDescription(/server.*filesystem/i);
  expect(screen.queryByRole("button")).not.toBeInTheDocument();
});

test("a target picker works after React replays mount effects", async () => {
  environment.open.mockResolvedValue("/chosen");
  render(<StrictMode><Picker /></StrictMode>);
  fireEvent.click(screen.getByRole("button", { name: "Choose folder…" }));
  await waitFor(() => expect(screen.getByRole("textbox", { name: "Scan target path" })).toHaveValue("/chosen"));
});

test("a dialog resolving after the field is disabled cannot change the target or leave the picker stuck", async () => {
  let finish!: (value: string) => void;
  environment.open.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const change = vi.fn();
  const view = render(<FolderPicker value="/retained" onChange={change} />);
  fireEvent.click(screen.getByRole("button", { name: "Choose folder…" }));
  view.rerender(<FolderPicker value="/retained" onChange={change} disabled />);
  finish("/late");
  await waitFor(() => expect(screen.getByRole("textbox")).toHaveValue("/retained"));
  view.rerender(<FolderPicker value="/retained" onChange={change} />);
  await waitFor(() => expect(screen.getByRole("button", { name: "Choose folder…" })).toBeEnabled());
  expect(change).not.toHaveBeenCalled();
});

test("an old dialog cannot overwrite the target after a disable and re-enable cycle", async () => {
  let finish!: (value: string) => void;
  environment.open.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const change = vi.fn();
  const view = render(<FolderPicker value="/retained" onChange={change} />);
  fireEvent.click(screen.getByRole("button", { name: "Choose folder…" }));
  view.rerender(<FolderPicker value="/retained" onChange={change} disabled />);
  view.rerender(<FolderPicker value="/retained" onChange={change} />);
  await act(async () => finish("/late"));
  expect(change).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Choose folder…" })).toBeEnabled();
});

test("a dialog cannot replace a newer typed or externally selected target", async () => {
  let finish!: (value: string) => void;
  environment.open.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const change = vi.fn();
  const view = render(<FolderPicker value="/retained" onChange={change} />);
  fireEvent.click(screen.getByRole("button", { name: "Choose folder…" }));
  view.rerender(<FolderPicker value="/newer" onChange={change} />);
  await act(async () => finish("/late"));
  expect(change).not.toHaveBeenCalled();
  expect(screen.getByRole("textbox")).toHaveValue("/newer");
});
