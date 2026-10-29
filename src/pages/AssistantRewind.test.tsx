import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn(() => new Promise(() => {})) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));

import { api } from "../lib/api";
import { useAppStore } from "../lib/stores";
import type { SessionInfo, StoredMessage } from "../lib/types";
import { AssistantPage } from "./Assistant";

const session: SessionInfo = {
  id: "s1",
  title: "Chat",
  autoTitle: false,
  createdAt: "2026-10-01T00:00:00Z",
  updatedAt: "2026-10-01T00:00:00Z",
  messageCount: 4,
  projectPath: null,
};

const messages: StoredMessage[] = [
  { id: "m1", role: "user", content: "first question", at: "2026-10-01T00:00:00Z" },
  { id: "m2", role: "assistant", content: "first answer", at: "2026-10-01T00:00:01Z" },
  { id: "m3", role: "user", content: "second question", at: "2026-10-01T00:00:02Z" },
  { id: "m4", role: "assistant", content: "second answer", at: "2026-10-01T00:00:03Z" },
];

let truncate: ReturnType<typeof vi.fn>;

beforeEach(() => {
  useAppStore.setState({ settings: null, assistantHandoff: null, aiReadiness: { status: "ready", version: 0 } } as never);
  vi.spyOn(api, "sessionList").mockResolvedValue([session]);
  vi.spyOn(api, "sessionGetMessages").mockResolvedValue(messages);
  vi.spyOn(api, "setActiveProject").mockResolvedValue(undefined as never);
  vi.spyOn(api, "todoList").mockResolvedValue([]);
  vi.spyOn(api, "getConversationUsage").mockResolvedValue(null as never);
  truncate = vi.fn().mockResolvedValue(undefined);
  vi.spyOn(api, "sessionTruncate").mockImplementation(truncate as never);
});

async function rewindButtons() {
  await screen.findByText("second question");
  return screen.getAllByRole("button", { name: "Rewind the conversation to this message" });
}

test("rewind asks for confirmation and cancelling keeps the conversation", async () => {
  render(<AssistantPage />);
  const [first] = await rewindButtons();
  await userEvent.click(first);
  const dialog = await screen.findByRole("alertdialog");
  expect(within(dialog).getByText(/permanently removes 4 messages/i)).toBeInTheDocument();
  expect(truncate).not.toHaveBeenCalled();
  await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
  expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  expect(truncate).not.toHaveBeenCalled();
  expect(screen.getByText("second answer")).toBeInTheDocument();
});

test("confirming rewinds and restores the message into an empty composer", async () => {
  render(<AssistantPage />);
  const buttons = await rewindButtons();
  await userEvent.click(buttons[1]);
  const dialog = await screen.findByRole("alertdialog");
  expect(within(dialog).queryByText(/draft/i)).not.toBeInTheDocument();
  await userEvent.click(within(dialog).getByRole("button", { name: "Rewind" }));
  await waitFor(() => expect(truncate).toHaveBeenCalledWith("s1", 2));
  expect(screen.queryByText("second answer")).not.toBeInTheDocument();
  expect((document.getElementById("assistant-composer") as HTMLTextAreaElement).value).toBe("second question");
});

test("a non-empty draft is only replaced when the confirmation says so", async () => {
  render(<AssistantPage />);
  const buttons = await rewindButtons();
  const composer = document.getElementById("assistant-composer") as HTMLTextAreaElement;
  await userEvent.type(composer, "my unsent draft");
  expect(composer.value).toBe("my unsent draft");
  await userEvent.click(buttons[1]);
  const dialog = await screen.findByRole("alertdialog");
  expect(within(dialog).getByText(/unsent draft will be replaced/i)).toBeInTheDocument();
  await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
  expect(composer.value).toBe("my unsent draft");

  await userEvent.click(buttons[1]);
  await userEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Rewind" }));
  await waitFor(() => expect(truncate).toHaveBeenCalledWith("s1", 2));
  await act(async () => {});
  expect(composer.value).toBe("second question");
});
