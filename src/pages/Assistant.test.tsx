import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";

/**
 * Page-level tests for the Assistant.
 *
 * The page is driven through the real `streamChat` event router in
 * `lib/aiEvents.ts`: only the Tauri event bus and the `api` commands are
 * replaced. A test starts a turn the way a person does (typing into the
 * composer), then plays the native side by emitting `ai://*` events for the
 * run id the page registered.
 */
const bus = vi.hoisted(() => {
  type Handler = (event: { payload: unknown }) => void;
  const handlers = new Map<string, Set<Handler>>();
  return {
    handlers,
    listen(event: string, handler: Handler) {
      let set = handlers.get(event);
      if (!set) {
        set = new Set();
        handlers.set(event, set);
      }
      set.add(handler);
      return () => {
        handlers.get(event)?.delete(handler);
      };
    },
    emit(event: string, payload: unknown) {
      for (const handler of [...(handlers.get(event) ?? [])]) handler({ payload });
    },
  };
});

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn(() => new Promise(() => {})) }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: async (event: string, handler: (event: { payload: unknown }) => void) =>
    bus.listen(event, handler),
}));

import { api } from "../lib/api";
import { useAppStore, useToastStore } from "../lib/stores";
import type { AiReadinessStatus } from "../lib/settingsRequests";
import type { ChatRequest, SessionInfo, StoredMessage } from "../lib/types";
import { AssistantPage } from "./Assistant";

function sessionInfo(id: string, title: string, updatedAt: string, messageCount = 0): SessionInfo {
  return {
    id,
    title,
    autoTitle: false,
    createdAt: "2026-10-01T00:00:00Z",
    updatedAt,
    messageCount,
    projectPath: null,
  };
}

const triage = sessionInfo("s1", "Triage chat", "2026-10-02T00:00:00Z", 2);
const older = sessionInfo("s2", "Older chat", "2026-10-01T00:00:00Z", 2);

const transcripts: Record<string, StoredMessage[]> = {
  s1: [
    { id: "m1", role: "user", content: "Is this SQL injection exploitable?", at: "2026-10-02T00:00:00Z" },
    { id: "m2", role: "assistant", content: "Yes, the answer depends on the driver.", at: "2026-10-02T00:00:01Z" },
  ],
  s2: [
    { id: "m3", role: "user", content: "Review the login flow", at: "2026-10-01T00:00:00Z" },
    { id: "m4", role: "assistant", content: "The session cookie lacks HttpOnly.", at: "2026-10-01T00:00:01Z" },
  ],
};

let streamChat: ReturnType<typeof vi.fn>;
let sessionAppend: ReturnType<typeof vi.fn>;
let sessionList: ReturnType<typeof vi.fn>;
let sessionCreate: ReturnType<typeof vi.fn>;

function setReadiness(status: AiReadinessStatus) {
  useAppStore.setState({ aiReadiness: { status, version: 0 } } as never);
}

beforeEach(() => {
  bus.handlers.clear();
  useAppStore.setState({
    settings: null,
    assistantHandoff: null,
    page: "assistant",
    aiReadiness: { status: "ready", version: 0 },
  } as never);
  useToastStore.setState({ toasts: [] });

  sessionList = vi.fn().mockResolvedValue([triage, older]);
  vi.spyOn(api, "sessionList").mockImplementation(sessionList as never);
  vi.spyOn(api, "sessionGetMessages").mockImplementation(
    (async (id: string) => transcripts[id] ?? []) as never,
  );
  sessionCreate = vi
    .fn()
    .mockResolvedValue(sessionInfo("s-new", "New conversation", "2026-10-03T00:00:00Z"));
  vi.spyOn(api, "sessionCreate").mockImplementation(sessionCreate as never);
  sessionAppend = vi.fn(async (id: string) =>
    id === "s2" ? older : { ...triage, id, updatedAt: "2026-10-02T00:00:00Z" },
  );
  vi.spyOn(api, "sessionAppend").mockImplementation(sessionAppend as never);
  vi.spyOn(api, "setActiveProject").mockResolvedValue(undefined as never);
  vi.spyOn(api, "todoList").mockResolvedValue([]);
  vi.spyOn(api, "getConversationUsage").mockResolvedValue(null as never);
  vi.spyOn(api, "cancelChat").mockResolvedValue(undefined as never);
  vi.spyOn(api, "respondPermission").mockResolvedValue(undefined as never);
  streamChat = vi.fn(async (_request: ChatRequest, runId?: string) => ({ runId: runId! }));
  vi.spyOn(api, "streamChat").mockImplementation(streamChat as never);
});

function composer() {
  return screen.getByRole("textbox", { name: "Message the AI Assistant" });
}

function sidebar() {
  return screen.getByRole("complementary", { name: "Chat sessions" });
}

function toastMessages() {
  return useToastStore.getState().toasts.map((toast) => `${toast.kind}: ${toast.message}`);
}

/** Render and wait until the newest session is active and its transcript shown. */
async function renderLoaded() {
  const user = userEvent.setup();
  render(<AssistantPage />);
  await screen.findByText("Yes, the answer depends on the driver.");
  await waitFor(() => expect(composer()).toBeEnabled());
  return user;
}

/** The run id of the n-th streamed turn, once the page has invoked it. */
async function runIdOf(call = 0): Promise<string> {
  await waitFor(() => expect(streamChat.mock.calls.length).toBeGreaterThan(call));
  return streamChat.mock.calls[call][1] as string;
}

function emitEvent(runId: string, event: Record<string, unknown>) {
  act(() => bus.emit("ai://event", { runId, ...event }));
}

function emitDone(runId: string, content: string, model: string | null = "test-model") {
  act(() => bus.emit("ai://done", { runId, content, model, usage: null }));
}

function emitError(runId: string, message: string) {
  act(() => bus.emit("ai://error", { runId, message }));
}

async function sendMessage(user: ReturnType<typeof userEvent.setup>, text: string) {
  const turn = streamChat.mock.calls.length;
  await user.type(composer(), `${text}{Enter}`);
  return runIdOf(turn);
}

describe("sending and streaming", () => {
  test("a sent message streams the reply into the transcript and persists both turns", async () => {
    const user = await renderLoaded();
    const runId = await sendMessage(user, "Which parameter is injectable?");

    const [request] = streamChat.mock.calls[0] as [ChatRequest];
    expect(request.conversationId).toBe("s1");
    expect(request.messages.map((message) => message.content)).toEqual([
      "Is this SQL injection exploitable?",
      "Yes, the answer depends on the driver.",
      "Which parameter is injectable?",
    ]);
    expect(screen.getByText("Which parameter is injectable?")).toBeInTheDocument();
    expect(composer()).toHaveValue("");
    expect(screen.getByText("Waiting for response…")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cancel the running turn" })).toBeInTheDocument();

    emitEvent(runId, { type: "delta", content: "The `id` " });
    emitEvent(runId, { type: "delta", content: "parameter." });
    expect(screen.getByText(/parameter\./)).toBeInTheDocument();
    expect(screen.queryByText("Waiting for response…")).not.toBeInTheDocument();

    emitDone(runId, "The id parameter is injectable.");
    expect(await screen.findByText("The id parameter is injectable.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Cancel the running turn" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send message" })).toBeInTheDocument();
    // The model name from the done event replaces the generic readiness label.
    expect(screen.getAllByText("test-model").length).toBeGreaterThan(0);

    await waitFor(() => expect(sessionAppend).toHaveBeenCalledTimes(2));
    expect(sessionAppend.mock.calls.map(([id, message]) => [id, message.role, message.content])).toEqual([
      ["s1", "user", "Which parameter is injectable?"],
      ["s1", "assistant", "The id parameter is injectable."],
    ]);
  });

  test("Shift+Enter adds a new line instead of sending", async () => {
    const user = await renderLoaded();
    await user.type(composer(), "line one{Shift>}{Enter}{/Shift}line two");
    expect(composer()).toHaveValue("line one\nline two");
    expect(streamChat).not.toHaveBeenCalled();
  });

  test("a suggestion starts a turn in an empty conversation", async () => {
    sessionList.mockResolvedValue([sessionInfo("s3", "Empty", "2026-10-02T00:00:00Z")]);
    const user = userEvent.setup();
    render(<AssistantPage />);
    const suggestion = await screen.findByRole("button", { name: /pickle\.loads/ });
    await waitFor(() => expect(suggestion).toBeEnabled());
    await user.click(suggestion);
    await runIdOf();
    const { messages } = streamChat.mock.calls[0][0] as ChatRequest;
    expect(messages[messages.length - 1].content).toMatch(/pickle\.loads/);
  });

  test("reasoning, tool calls and the agent plan are shown while the turn runs", async () => {
    const user = await renderLoaded();
    const runId = await sendMessage(user, "Scan the project");

    emitEvent(runId, { type: "reasoning", content: "Looking at the sinks" });
    expect(screen.getByText("Reasoning…")).toBeInTheDocument();

    emitEvent(runId, { type: "tool_start", toolCallId: "t1", name: "grep_project", arguments: '{"q":"exec"}' });
    const activity = screen.getByRole("complementary", { name: "Assistant activity" });
    expect(within(activity).getByRole("button", { name: /grep_project\s*Running/ })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /grep_project/ }).length).toBe(2);

    emitEvent(runId, {
      type: "tool_result",
      toolCallId: "t1",
      name: "grep_project",
      success: true,
      durationMs: 12,
      resultPreview: "src/run.py:4",
    });
    expect(within(activity).getByRole("button", { name: /grep_project\s*Completed/ })).toBeInTheDocument();

    emitEvent(runId, {
      type: "todos",
      items: [
        { id: 1, text: "Find sinks", status: "done" },
        { id: 2, text: "Trace inputs", status: "pending" },
      ],
    });
    expect(within(activity).getByRole("region", { name: "Agent plan" })).toHaveTextContent("1/2");
    expect(within(activity).getByText("Trace inputs")).toBeInTheDocument();

    emitDone(runId, "Done scanning.");
    await screen.findByText("Done scanning.");
    // The finished answer keeps its tool cards.
    expect(screen.getAllByRole("button", { name: /grep_project/ }).length).toBe(2);
  });

  test("a permission request opens the approval dialog and reports the decision", async () => {
    const user = await renderLoaded();
    const runId = await sendMessage(user, "Fetch the advisory");
    emitEvent(runId, {
      type: "permission_request",
      requestId: "perm-1",
      tool: "web_fetch",
      arguments: '{"url":"https://example.test"}',
    });
    const dialog = await screen.findByRole("dialog", { name: "Tool permission required" });
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));
    expect(api.respondPermission).toHaveBeenCalledWith("perm-1", true);
    expect(screen.queryByRole("dialog", { name: "Tool permission required" })).not.toBeInTheDocument();
  });

  test("an ask_user request opens the question dialog, and the turn ending closes it", async () => {
    const user = await renderLoaded();
    const runId = await sendMessage(user, "Help me scope this");
    emitEvent(runId, {
      type: "ask_user",
      requestId: "ask-1",
      questions: [{ prompt: "Which service?", options: ["api", "web"] }],
    });
    const dialog = await screen.findByRole("dialog", { name: "The AI has questions" });
    expect(within(dialog).getByText("Which service?")).toBeInTheDocument();
    emitDone(runId, "Proceeding without an answer.");
    await waitFor(() =>
      expect(screen.queryByRole("dialog", { name: "The AI has questions" })).not.toBeInTheDocument(),
    );
  });
});

describe("steering and follow-ups", () => {
  test("a message sent mid-run is queued, then folded into the transcript", async () => {
    const steerChat = vi.spyOn(api, "steerChat").mockResolvedValue(true);
    const user = await renderLoaded();
    const runId = await sendMessage(user, "Audit the uploads handler");

    expect(composer()).toHaveAccessibleDescription(/Enter to steer the running turn/);
    await user.type(composer(), "focus on path traversal{Enter}");
    expect(steerChat).toHaveBeenCalledWith(runId, "focus on path traversal");
    const queued = await screen.findByRole("list", { name: "Queued messages" });
    expect(within(queued).getByText("focus on path traversal")).toBeInTheDocument();
    expect(composer()).toHaveValue("");

    emitEvent(runId, { type: "steer", text: "focus on path traversal" });
    expect(screen.queryByRole("list", { name: "Queued messages" })).not.toBeInTheDocument();
    expect(screen.getByText("steered mid-run")).toBeInTheDocument();
    expect(screen.getByText("focus on path traversal")).toBeInTheDocument();
    await waitFor(() =>
      expect(sessionAppend).toHaveBeenCalledWith("s1", expect.objectContaining({ content: "focus on path traversal" })),
    );
  });

  test("a message the finishing run declines is sent as the next turn", async () => {
    vi.spyOn(api, "steerChat").mockResolvedValue(false);
    const user = await renderLoaded();
    const runId = await sendMessage(user, "Summarize the findings");
    await user.type(composer(), "and rank them{Enter}");

    emitDone(runId, "Three findings.");
    const followUpRun = await runIdOf(1);
    expect(followUpRun).not.toBe(runId);
    const [request] = streamChat.mock.calls[1] as [ChatRequest];
    expect(request.messages.slice(-2).map((message) => message.content)).toEqual([
      "Three findings.",
      "and rank them",
    ]);
  });

  test("a steer that cannot be delivered returns the text to the composer", async () => {
    vi.spyOn(api, "steerChat").mockRejectedValue(new Error("run registry unavailable"));
    const user = await renderLoaded();
    await sendMessage(user, "Check the CSP");
    await user.type(composer(), "include report-uri{Enter}");
    await waitFor(() => expect(composer()).toHaveValue("include report-uri"));
    expect(toastMessages()).toContain(
      "error: That message could not be sent: run registry unavailable",
    );
  });
});

describe("cancelling and stream errors", () => {
  test("cancelling asks the native run to stop and keeps the partial answer", async () => {
    const user = await renderLoaded();
    const runId = await sendMessage(user, "Write a long report");
    emitEvent(runId, { type: "delta", content: "Section one" });

    await user.click(screen.getByRole("button", { name: "Cancel the running turn" }));
    await waitFor(() => expect(api.cancelChat).toHaveBeenCalledWith(runId));

    emitError(runId, "Run cancelled");
    expect(await screen.findByText(/interrupted \(Run cancelled\)/)).toBeInTheDocument();
    expect(screen.getByText("Section one")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send message" })).toBeInTheDocument();
    // A cancellation is the user's own action, not an error to report.
    expect(toastMessages()).toEqual([]);
  });

  test("a cancellation before any output leaves no message and no error", async () => {
    const user = await renderLoaded();
    const runId = await sendMessage(user, "Never mind");
    await user.click(screen.getByRole("button", { name: "Cancel the running turn" }));
    emitError(runId, "Run cancelled by user");
    await waitFor(() => expect(screen.getByRole("button", { name: "Send message" })).toBeInTheDocument());
    expect(screen.queryByText(/interrupted/)).not.toBeInTheDocument();
    expect(toastMessages()).toEqual([]);
  });

  test("a stream error before any output is reported and the composer recovers", async () => {
    const user = await renderLoaded();
    const runId = await sendMessage(user, "Explain CVE-2024-3094");
    emitError(runId, "Provider returned 401");
    await waitFor(() => expect(toastMessages()).toEqual(["error: Provider returned 401"]));
    expect(screen.queryByText("Waiting for response…")).not.toBeInTheDocument();
    expect(composer()).toBeEnabled();
  });

  test("a stream error after partial output keeps it, marked as interrupted", async () => {
    const user = await renderLoaded();
    const runId = await sendMessage(user, "Explain CVE-2024-3094");
    emitEvent(runId, { type: "delta", content: "The backdoor lives in liblzma" });
    emitError(runId, "connection reset");
    expect(await screen.findByText(/interrupted \(connection reset\)/)).toBeInTheDocument();
    expect(screen.getByText(/The backdoor lives in liblzma/)).toBeInTheDocument();
  });

  test("a failure to start the stream is reported", async () => {
    streamChat.mockRejectedValue(new Error("AI endpoint refused the connection"));
    const user = await renderLoaded();
    await user.type(composer(), "hello{Enter}");
    await waitFor(() =>
      expect(toastMessages()).toEqual(["error: AI endpoint refused the connection"]),
    );
    expect(screen.getByRole("button", { name: "Send message" })).toBeInTheDocument();
  });

  test("events for another run are ignored", async () => {
    const user = await renderLoaded();
    const runId = await sendMessage(user, "What is SSRF?");
    emitEvent("someone-else", { type: "delta", content: "stray text" });
    act(() => bus.emit("ai://done", { runId: "someone-else", content: "stray", model: null, usage: null }));
    expect(screen.queryByText("stray text")).not.toBeInTheDocument();
    expect(screen.getByText("Waiting for response…")).toBeInTheDocument();
    emitDone(runId, "Server-side request forgery.");
    expect(await screen.findByText("Server-side request forgery.")).toBeInTheDocument();
  });
});

describe("AI readiness", () => {
  test("an unconfigured provider pauses sending and links to Settings", async () => {
    setReadiness("unconfigured");
    const user = userEvent.setup();
    render(<AssistantPage />);
    await screen.findByText("Yes, the answer depends on the driver.");
    expect(screen.getByRole("status")).toHaveTextContent(/Configure an AI provider before sending a message/);
    expect(composer()).toBeDisabled();
    expect(composer()).toHaveAttribute("placeholder", "Configure an AI provider to send messages");
    expect(screen.getByRole("button", { name: "Send message" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Open Settings" }));
    expect(useAppStore.getState().page).toBe("settings");
  });

  test("an offline endpoint is announced as an alert", async () => {
    setReadiness("offline");
    render(<AssistantPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/cannot be reached/);
    expect(screen.getAllByText("AI endpoint unavailable").length).toBeGreaterThan(0);
  });

  test("server mode explains that AI runs only in the desktop app", async () => {
    setReadiness("unsupported");
    render(<AssistantPage />);
    await screen.findByText("Yes, the answer depends on the driver.");
    expect(screen.getByRole("alert")).toHaveTextContent(
      "AI is available in the oxAudit desktop app; this server does not accept AI requests.",
    );
    // There is nothing to configure in a server build.
    expect(screen.queryByRole("button", { name: "Open Settings" })).not.toBeInTheDocument();
    expect(composer()).toBeDisabled();
  });

  test("readiness becoming ready re-enables the composer", async () => {
    setReadiness("checking");
    render(<AssistantPage />);
    await screen.findByText("Yes, the answer depends on the driver.");
    expect(composer()).toBeDisabled();
    act(() => setReadiness("ready"));
    await waitFor(() => expect(composer()).toBeEnabled());
    expect(screen.queryByRole("status", { name: /checking/ })).not.toBeInTheDocument();
  });
});

describe("sessions", () => {
  test("the newest session opens with its transcript and the list shows every session", async () => {
    await renderLoaded();
    const list = sidebar();
    expect(within(list).getByRole("button", { name: /^Triage chat/ })).toHaveAttribute("aria-current", "true");
    expect(within(list).getByRole("button", { name: /^Older chat/ })).not.toHaveAttribute("aria-current");
    expect(screen.getByRole("heading", { name: "Triage chat" })).toBeInTheDocument();
    expect(api.todoList).toHaveBeenCalledWith("s1");
  });

  test("an empty session store starts a fresh conversation", async () => {
    sessionList.mockResolvedValue([]);
    render(<AssistantPage />);
    expect(await screen.findByRole("heading", { name: "New conversation" })).toBeInTheDocument();
    expect(sessionCreate).toHaveBeenCalledWith(null, null);
    expect(screen.getByText("What would you like to audit?")).toBeInTheDocument();
  });

  test("selecting another session loads its transcript", async () => {
    const user = await renderLoaded();
    await user.click(within(sidebar()).getByRole("button", { name: /^Older chat/ }));
    expect(await screen.findByText("The session cookie lacks HttpOnly.")).toBeInTheDocument();
    expect(screen.queryByText("Yes, the answer depends on the driver.")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Older chat" })).toBeInTheDocument();
    expect(api.todoList).toHaveBeenCalledWith("s2");

    // The next turn goes to the selected conversation.
    await waitFor(() => expect(composer()).toBeEnabled());
    await sendMessage(user, "Is SameSite enough?");
    expect((streamChat.mock.calls[0][0] as ChatRequest).conversationId).toBe("s2");
  });

  test("New chat creates and opens an empty conversation", async () => {
    const user = await renderLoaded();
    await user.click(within(sidebar()).getByRole("button", { name: "New chat" }));
    expect(await screen.findByRole("heading", { name: "New conversation" })).toBeInTheDocument();
    expect(screen.getByText("What would you like to audit?")).toBeInTheDocument();
    expect(within(sidebar()).getByRole("button", { name: /^New conversation/ })).toHaveAttribute(
      "aria-current",
      "true",
    );
  });

  test("session controls are locked while a turn runs", async () => {
    const user = await renderLoaded();
    await sendMessage(user, "Long task");
    expect(within(sidebar()).getByRole("button", { name: "New chat" })).toBeDisabled();
    expect(within(sidebar()).getByRole("button", { name: /^Older chat/ })).toBeDisabled();
    expect(within(sidebar()).queryByRole("button", { name: "Delete Older chat" })).not.toBeInTheDocument();
    expect(within(sidebar()).getByRole("status", { name: "Assistant is responding" })).toBeInTheDocument();
  });

  test("deleting another session removes it after the delete persists", async () => {
    const sessionDelete = vi.spyOn(api, "sessionDelete").mockResolvedValue(undefined);
    const user = await renderLoaded();
    await user.click(within(sidebar()).getByRole("button", { name: "Delete Older chat" }));
    await user.click(within(sidebar()).getByRole("button", { name: "Yes" }));
    expect(sessionDelete).toHaveBeenCalledWith("s2");
    await waitFor(() =>
      expect(within(sidebar()).queryByRole("button", { name: /^Older chat/ })).not.toBeInTheDocument(),
    );
    expect(screen.getByText("Yes, the answer depends on the driver.")).toBeInTheDocument();
    expect(sessionCreate).not.toHaveBeenCalled();
  });

  test("deleting the active session opens a fresh one", async () => {
    vi.spyOn(api, "sessionDelete").mockResolvedValue(undefined);
    const user = await renderLoaded();
    await user.click(within(sidebar()).getByRole("button", { name: "Delete Triage chat" }));
    await user.click(within(sidebar()).getByRole("button", { name: "Yes" }));
    expect(await screen.findByRole("heading", { name: "New conversation" })).toBeInTheDocument();
    expect(screen.queryByText("Yes, the answer depends on the driver.")).not.toBeInTheDocument();
    expect(within(sidebar()).queryByRole("button", { name: /^Triage chat/ })).not.toBeInTheDocument();
  });

  test("a failed delete keeps the session and reports why", async () => {
    vi.spyOn(api, "sessionDelete").mockRejectedValue(new Error("file is locked"));
    const user = await renderLoaded();
    await user.click(within(sidebar()).getByRole("button", { name: "Delete Older chat" }));
    await user.click(within(sidebar()).getByRole("button", { name: "Yes" }));
    await waitFor(() =>
      expect(toastMessages()).toEqual(["error: Could not delete the conversation: file is locked"]),
    );
    expect(within(sidebar()).getByRole("button", { name: /^Older chat/ })).toBeInTheDocument();
  });

  test("deleting the active session when a replacement cannot be created stops sending to it", async () => {
    vi.spyOn(api, "sessionDelete").mockResolvedValue(undefined);
    sessionCreate.mockRejectedValue(new Error("disk full"));
    const user = await renderLoaded();
    await user.click(within(sidebar()).getByRole("button", { name: "Delete Triage chat" }));
    await user.click(within(sidebar()).getByRole("button", { name: "Yes" }));
    await waitFor(() => expect(toastMessages()).toEqual(["error: disk full"]));

    // The deleted conversation must not stay on screen or keep receiving turns.
    expect(screen.queryByText("Yes, the answer depends on the driver.")).not.toBeInTheDocument();
    expect(composer()).toBeDisabled();
    expect(composer()).toHaveAccessibleDescription(/start a new chat/i);
    expect(screen.getByRole("button", { name: "Send message" })).toBeDisabled();
  });

  test("renaming adopts the new title only after it persists", async () => {
    const rename = vi.spyOn(api, "sessionRename").mockResolvedValue(undefined);
    const user = await renderLoaded();
    await user.click(within(sidebar()).getByRole("button", { name: "Rename Triage chat" }));
    const field = within(sidebar()).getByRole("textbox", { name: "Rename Triage chat" });
    await user.clear(field);
    await user.type(field, "SQLi triage{Enter}");
    expect(rename).toHaveBeenCalledWith("s1", "SQLi triage");
    expect(await screen.findByRole("heading", { name: "SQLi triage" })).toBeInTheDocument();
  });

  test("a failed rename keeps the old title", async () => {
    vi.spyOn(api, "sessionRename").mockRejectedValue(new Error("read-only store"));
    const user = await renderLoaded();
    await user.click(within(sidebar()).getByRole("button", { name: "Rename Triage chat" }));
    const field = within(sidebar()).getByRole("textbox", { name: "Rename Triage chat" });
    await user.clear(field);
    await user.type(field, "Renamed{Enter}");
    await waitFor(() =>
      expect(toastMessages()).toEqual(["error: Could not rename the conversation: read-only store"]),
    );
    expect(screen.getByRole("heading", { name: "Triage chat" })).toBeInTheDocument();
  });

  test("clearing the conversation truncates the stored transcript", async () => {
    const truncate = vi.spyOn(api, "sessionTruncate").mockResolvedValue(undefined);
    const user = await renderLoaded();
    await user.click(screen.getByRole("button", { name: "Clear conversation" }));
    expect(truncate).toHaveBeenCalledWith("s1", 0);
    expect(await screen.findByText("What would you like to audit?")).toBeInTheDocument();
  });

  test("a session that cannot be opened reports the failure and keeps the current one", async () => {
    const user = await renderLoaded();
    vi.mocked(api.sessionGetMessages).mockRejectedValueOnce(new Error("corrupt transcript"));
    await user.click(within(sidebar()).getByRole("button", { name: /^Older chat/ }));
    await waitFor(() => expect(toastMessages()).toEqual(["error: corrupt transcript"]));
    expect(screen.getByText("Yes, the answer depends on the driver.")).toBeInTheDocument();
    expect(composer()).toBeEnabled();
  });
});

describe("loading sessions fails", () => {
  test("the sidebar shows a persistent error with Retry instead of the empty state", async () => {
    sessionList.mockRejectedValueOnce(new Error("database is locked"));
    const user = userEvent.setup();
    render(<AssistantPage />);

    const alert = await within(sidebar()).findByRole("alert");
    expect(alert).toHaveTextContent(/Conversations could not be loaded/);
    expect(alert).toHaveTextContent(/database is locked/);
    expect(within(sidebar()).queryByText("Your security conversations will appear here.")).not.toBeInTheDocument();

    // Sending needs a conversation; the composer says so instead of silently
    // refusing the Send.
    expect(composer()).toBeDisabled();
    expect(composer()).toHaveAccessibleDescription(/could not be loaded/i);
    expect(screen.getByRole("button", { name: "Send message" })).toBeDisabled();

    await user.click(within(alert).getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("Yes, the answer depends on the driver.")).toBeInTheDocument();
    expect(within(sidebar()).queryByRole("alert")).not.toBeInTheDocument();
    await waitFor(() => expect(composer()).toBeEnabled());
    expect(composer()).toHaveAccessibleDescription(/Enter to send/);
  });

  test("a retry that fails again keeps the error visible with the new reason", async () => {
    sessionList
      .mockRejectedValueOnce(new Error("database is locked"))
      .mockRejectedValueOnce(new Error("still locked"));
    const user = userEvent.setup();
    render(<AssistantPage />);
    const alert = await within(sidebar()).findByRole("alert");
    await user.click(within(alert).getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(within(sidebar()).getByRole("alert")).toHaveTextContent(/still locked/));
    expect(composer()).toBeDisabled();
  });

  test("starting a new chat still works when the list could not be loaded", async () => {
    sessionList.mockRejectedValueOnce(new Error("database is locked"));
    const user = userEvent.setup();
    render(<AssistantPage />);
    await within(sidebar()).findByRole("alert");
    await user.click(within(sidebar()).getByRole("button", { name: "New chat" }));
    expect(await screen.findByRole("heading", { name: "New conversation" })).toBeInTheDocument();
    await waitFor(() => expect(composer()).toBeEnabled());
  });
});

describe("attaching context", () => {
  const handoff = {
    id: "h1",
    label: "Finding: SQL injection in users.py",
    content: "cursor.execute(f\"SELECT * FROM users WHERE id={uid}\")",
    projectPath: "/work/repo",
  };

  test("a handoff from another page opens the review dialog and attaches on confirm", async () => {
    useAppStore.setState({ assistantHandoff: handoff } as never);
    const user = userEvent.setup();
    render(<AssistantPage />);

    const dialog = await screen.findByRole("dialog", { name: "Review context before attaching" });
    expect(within(dialog).getByText(handoff.label)).toBeInTheDocument();
    expect(within(dialog).getByText("Source scope: /work/repo")).toBeInTheDocument();
    expect(within(dialog).getByRole("textbox", { name: "Context content" })).toHaveValue(handoff.content);
    // Consumed, so returning to the page does not reopen it.
    expect(useAppStore.getState().assistantHandoff).toBeNull();

    const attach = within(dialog).getByRole("button", { name: "Attach context" });
    await waitFor(() => expect(attach).toBeEnabled());
    await user.click(attach);

    await waitFor(() =>
      expect(screen.queryByRole("dialog", { name: "Review context before attaching" })).not.toBeInTheDocument(),
    );
    const [sessionId, stored] = sessionAppend.mock.calls[0];
    expect(sessionId).toBe("s1");
    expect(stored.content).toBe(`[User-attached source context: ${handoff.label}]\n\n${handoff.content}`);
    expect(screen.getByText(/User-attached source context: Finding: SQL injection/)).toBeInTheDocument();
    // Attaching never sends anything to the model on its own.
    expect(streamChat).not.toHaveBeenCalled();
  });

  test("context edited in the dialog is what gets attached", async () => {
    useAppStore.setState({ assistantHandoff: handoff } as never);
    const user = userEvent.setup();
    render(<AssistantPage />);
    const dialog = await screen.findByRole("dialog", { name: "Review context before attaching" });
    // The dialog focuses Close one frame after opening. Typing before that lands
    // would send a space to Close mid-word, which no person types fast enough to do.
    await waitFor(() => expect(within(dialog).getByRole("button", { name: "Close" })).toHaveFocus());
    const field = within(dialog).getByRole("textbox", { name: "Context content" });
    await user.clear(field);
    await user.type(field, "redacted snippet");
    await waitFor(() => expect(within(dialog).getByRole("button", { name: "Attach context" })).toBeEnabled());
    await user.click(within(dialog).getByRole("button", { name: "Attach context" }));
    await waitFor(() => expect(sessionAppend).toHaveBeenCalled());
    expect(sessionAppend.mock.calls[0][1].content).toMatch(/\n\nredacted snippet$/);
  });

  test("a handoff arriving while the page is open opens the dialog too", async () => {
    await renderLoaded();
    act(() => useAppStore.getState().openAssistant(handoff));
    expect(await screen.findByRole("dialog", { name: "Review context before attaching" })).toBeInTheDocument();
  });

  test("manual context can be dismissed with Escape without attaching", async () => {
    const user = await renderLoaded();
    const opener = screen.getByRole("button", { name: "Context" });
    await user.click(opener);
    const dialog = await screen.findByRole("dialog", { name: "Review context before attaching" });
    expect(within(dialog).getByText("Manual context")).toBeInTheDocument();
    await waitFor(() => expect(within(dialog).getByRole("button", { name: "Close" })).toHaveFocus());
    expect(within(dialog).getByRole("button", { name: "Attach context" })).toBeDisabled();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(sessionAppend).not.toHaveBeenCalled();
    await waitFor(() => expect(opener).toHaveFocus());
  });

  test("a failed attach keeps the dialog open and reports why", async () => {
    sessionAppend.mockRejectedValueOnce(new Error("transcript is read-only"));
    useAppStore.setState({ assistantHandoff: handoff } as never);
    const user = userEvent.setup();
    render(<AssistantPage />);
    const dialog = await screen.findByRole("dialog", { name: "Review context before attaching" });
    await waitFor(() => expect(within(dialog).getByRole("button", { name: "Attach context" })).toBeEnabled());
    await user.click(within(dialog).getByRole("button", { name: "Attach context" }));
    await waitFor(() =>
      expect(toastMessages()).toEqual(["error: Context could not be attached: transcript is read-only"]),
    );
    expect(screen.getByRole("dialog", { name: "Review context before attaching" })).toBeInTheDocument();
    expect(within(dialog).getByRole("textbox", { name: "Context content" })).toHaveValue(handoff.content);
  });
});

describe("conversation search", () => {
  test("search highlights matches and steps through them", async () => {
    const user = await renderLoaded();
    await user.click(screen.getByRole("button", { name: "Search conversation" }));
    const field = await screen.findByRole("searchbox", { name: "Search this conversation" });
    await waitFor(() => expect(field).toHaveFocus());

    await user.type(field, "the");
    const toolbar = screen.getByRole("search", { name: "Search conversation" });
    await waitFor(() => expect(toolbar).toHaveTextContent("1 / 2"));
    const marks = document.querySelectorAll("mark[data-chat-search-match]");
    expect(Array.from(marks, (mark) => mark.textContent?.toLowerCase())).toEqual(["the", "the"]);

    await user.keyboard("{Enter}");
    expect(toolbar).toHaveTextContent("2 / 2");
    await user.keyboard("{Enter}");
    expect(toolbar).toHaveTextContent("1 / 2");
    await user.keyboard("{Shift>}{Enter}{/Shift}");
    expect(toolbar).toHaveTextContent("2 / 2");

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("search", { name: "Search conversation" })).not.toBeInTheDocument();
    expect(document.querySelectorAll("mark[data-chat-search-match]")).toHaveLength(0);
  });

  test("Ctrl+F opens search and a query with no matches reports none", async () => {
    const user = await renderLoaded();
    await user.keyboard("{Control>}f{/Control}");
    const field = await screen.findByRole("searchbox", { name: "Search this conversation" });
    await waitFor(() => expect(field).toHaveFocus());
    await user.type(field, "kubernetes");
    const toolbar = screen.getByRole("search", { name: "Search conversation" });
    expect(toolbar).toHaveTextContent("0 / 0");
    expect(within(toolbar).getByRole("button", { name: "Next match" })).toBeDisabled();
  });
});
