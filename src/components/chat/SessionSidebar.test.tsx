import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import type { SessionInfo } from "../../lib/types";
import { SessionSidebar } from "./SessionSidebar";

function session(id: string, title: string, messageCount = 0): SessionInfo {
  return {
    id,
    title,
    autoTitle: false,
    createdAt: "2026-10-01T00:00:00Z",
    updatedAt: "2026-10-01T00:00:00Z",
    messageCount,
    projectPath: null,
  };
}

const sessions = [session("a", "XSS review", 3), session("b", "Dependency triage")];

beforeEach(() => {
  // The collapsed state is remembered across visits; start every test open.
  localStorage.clear();
});

function setup(props: Partial<Parameters<typeof SessionSidebar>[0]> = {}) {
  const handlers = {
    onSelect: vi.fn(),
    onCreate: vi.fn(),
    onRename: vi.fn(),
    onDelete: vi.fn(),
  };
  const user = userEvent.setup();
  const view = render(
    <SessionSidebar sessions={sessions} activeId="a" busy={false} {...handlers} {...props} />,
  );
  return { ...view, ...handlers, user };
}

function sessionButton(title: string) {
  return screen.getByRole("button", { name: new RegExp(`^${title}`) });
}

test("lists sessions in a labelled landmark and marks the active one", () => {
  setup();
  const aside = screen.getByRole("complementary", { name: "Chat sessions" });
  expect(within(aside).getByText("2")).toBeInTheDocument();
  expect(sessionButton("XSS review")).toHaveAttribute("aria-current", "true");
  expect(sessionButton("XSS review")).toHaveTextContent("3 msg");
  expect(sessionButton("Dependency triage")).not.toHaveAttribute("aria-current");
});

test("selecting and creating report through callbacks", async () => {
  const { user, onSelect, onCreate } = setup();
  await user.click(sessionButton("Dependency triage"));
  expect(onSelect).toHaveBeenCalledWith("b");
  await user.click(screen.getByRole("button", { name: "New chat" }));
  expect(onCreate).toHaveBeenCalledOnce();
});

test("an empty store shows the empty-state text", () => {
  setup({ sessions: [], activeId: null });
  expect(screen.getByText("Your security conversations will appear here.")).toBeInTheDocument();
});

test("search filters by title and explains when nothing matches", async () => {
  const { user } = setup();
  const toggle = screen.getByRole("button", { name: "Search chat sessions" });
  await user.click(toggle);
  const field = screen.getByRole("textbox", { name: "Search chat sessions" });
  expect(field).toHaveFocus();
  await user.type(field, "xss");
  expect(sessionButton("XSS review")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /^Dependency triage/ })).not.toBeInTheDocument();

  await user.clear(field);
  await user.type(field, "kubernetes");
  expect(screen.getByText("No matching conversations.")).toBeInTheDocument();

  // Closing search clears the filter.
  await user.click(screen.getByRole("button", { name: "Close session search" }));
  expect(sessionButton("Dependency triage")).toBeInTheDocument();
});

test("rename commits on Enter and is abandoned on Escape or an empty title", async () => {
  const { user, onRename } = setup();
  await user.click(screen.getByRole("button", { name: "Rename XSS review" }));
  let field = screen.getByRole("textbox", { name: "Rename XSS review" });
  expect(field).toHaveFocus();
  expect(field).toHaveValue("XSS review");
  await user.keyboard("{Escape}");
  expect(onRename).not.toHaveBeenCalled();

  await user.click(screen.getByRole("button", { name: "Rename XSS review" }));
  field = screen.getByRole("textbox", { name: "Rename XSS review" });
  await user.clear(field);
  await user.click(screen.getByRole("button", { name: "Save session name" }));
  expect(onRename).not.toHaveBeenCalled();

  await user.click(screen.getByRole("button", { name: "Rename XSS review" }));
  field = screen.getByRole("textbox", { name: "Rename XSS review" });
  await user.clear(field);
  await user.type(field, "  Stored XSS  {Enter}");
  expect(onRename).toHaveBeenCalledExactlyOnceWith("a", "Stored XSS");
});

test("delete needs a second confirmation step", async () => {
  const { user, onDelete } = setup();
  await user.click(screen.getByRole("button", { name: "Delete Dependency triage" }));
  expect(screen.getByText("Delete?")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "No" }));
  expect(onDelete).not.toHaveBeenCalled();
  expect(sessionButton("Dependency triage")).toBeInTheDocument();

  await user.click(screen.getByRole("button", { name: "Delete Dependency triage" }));
  await user.click(screen.getByRole("button", { name: "Yes" }));
  expect(onDelete).toHaveBeenCalledExactlyOnceWith("b");
});

test("while busy the controls lock and the active session shows it is responding", async () => {
  const { user, onSelect } = setup({ busy: true });
  expect(screen.getByRole("button", { name: "New chat" })).toBeDisabled();
  expect(sessionButton("Dependency triage")).toBeDisabled();
  expect(screen.queryByRole("button", { name: /^Rename/ })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /^Delete/ })).not.toBeInTheDocument();
  expect(screen.getByRole("status", { name: "Assistant is responding" })).toBeInTheDocument();
  await user.click(sessionButton("Dependency triage"));
  expect(onSelect).not.toHaveBeenCalled();
});

test("collapsing hides the list but keeps New chat reachable", async () => {
  const { user, onCreate } = setup();
  await user.click(screen.getByRole("button", { name: /Collapse conversation history/i }));
  // jsdom loads no stylesheet, so the list's `hidden` class cannot be observed
  // as invisibility; the expanded state and the dropped search toggle can.
  expect(screen.getByRole("button", { name: /Expand conversation history/i })).toHaveAttribute(
    "aria-expanded",
    "false",
  );
  expect(screen.queryByRole("button", { name: "Search chat sessions" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "New chat" }));
  expect(onCreate).toHaveBeenCalledOnce();
  await user.click(screen.getByRole("button", { name: /Expand conversation history/i }));
  expect(sessionButton("XSS review")).toBeInTheDocument();
});

test("a load error replaces the empty state with an alert and a Retry button", async () => {
  const onRetry = vi.fn();
  const { user } = setup({ sessions: [], activeId: null, loadError: "database is locked", onRetry });
  const alert = screen.getByRole("alert");
  expect(alert).toHaveTextContent("Conversations could not be loaded.");
  expect(alert).toHaveTextContent("database is locked");
  expect(screen.queryByText("Your security conversations will appear here.")).not.toBeInTheDocument();
  await user.click(within(alert).getByRole("button", { name: "Retry" }));
  expect(onRetry).toHaveBeenCalledOnce();
});

test("Retry is disabled while a load is already in progress", () => {
  setup({ sessions: [], activeId: null, loadError: "database is locked", onRetry: vi.fn(), disabled: true });
  expect(within(screen.getByRole("alert")).getByRole("button", { name: "Retry" })).toBeDisabled();
});
