import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn(() => new Promise(() => {})) }));

import { api } from "../../lib/api";
import type { AskQuestion } from "../../lib/types";
import { AskUserModal } from "./AskUserModal";

/**
 * The `ask_user` tool blocks the agent until this dialog answers or skips.
 * Every path out of it must report back to the pending interaction exactly
 * once, or the agent run hangs waiting on a request nobody will answer.
 */
describe("AskUserModal", () => {
  let respond: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    respond = vi.fn().mockResolvedValue(undefined);
    vi.spyOn(api, "respondInteraction").mockImplementation(respond as never);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function setup(questions: AskQuestion[], { fakeTimers = false } = {}) {
    const onClose = vi.fn();
    const onRestoreFocus = vi.fn();
    const user = fakeTimers ? null : userEvent.setup();
    const view = render(
      <AskUserModal
        requestId="req-1"
        questions={questions}
        onClose={onClose}
        onRestoreFocus={onRestoreFocus}
      />,
    );
    return { onClose, onRestoreFocus, user: user!, ...view };
  }

  /**
   * The dialog moves focus to Skip one animation frame after it opens. A test
   * that starts typing before then can have that frame land mid-keystroke, and
   * a typed space then presses Skip. Wait for the dialog to settle first, the
   * way a person would see it before answering.
   */
  async function open(questions: AskQuestion[]) {
    const view = setup(questions);
    await waitFor(() => expect(screen.getByRole("button", { name: "Skip" })).toHaveFocus());
    return view;
  }

  const freeText: AskQuestion[] = [{ prompt: "Which branch should I scan?" }];
  const single: AskQuestion[] = [{ prompt: "Pick a severity", options: ["High", "Low"] }];
  const multi: AskQuestion[] = [
    { prompt: "Which ecosystems?", options: ["npm", "cargo", "pip"], multi_select: true },
  ];

  test("is announced as a modal dialog with a name and description", () => {
    setup(freeText);
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAccessibleName("The AI has questions");
    expect(dialog).toHaveAccessibleDescription(/Answer every question to continue/);
    expect(screen.getByRole("group", { name: "Which branch should I scan?" })).toBeInTheDocument();
  });

  test("focuses Skip when it opens", async () => {
    setup(freeText);
    await waitFor(() => expect(screen.getByRole("button", { name: "Skip" })).toHaveFocus());
  });

  test("Skip reports an empty answer set and closes", async () => {
    const { onClose, user } = setup(freeText);
    await user.click(screen.getByRole("button", { name: "Skip" }));
    expect(respond).toHaveBeenCalledExactlyOnceWith("req-1", []);
    expect(onClose).toHaveBeenCalledOnce();
  });

  test("Escape skips the request", async () => {
    const { onClose, user } = setup(freeText);
    await user.keyboard("{Escape}");
    expect(respond).toHaveBeenCalledExactlyOnceWith("req-1", []);
    expect(onClose).toHaveBeenCalledOnce();
  });

  test("keeps Tab inside the dialog in both directions", async () => {
    const { user } = setup(single);
    const skip = screen.getByRole("button", { name: "Skip" });
    await waitFor(() => expect(skip).toHaveFocus());
    const high = screen.getByRole("button", { name: "High" });

    // Answer is disabled until something is chosen, so Skip is the last
    // focusable control and Tab must wrap back to the first option.
    expect(screen.getByRole("button", { name: "Answer" })).toBeDisabled();
    await user.tab();
    expect(high).toHaveFocus();

    await user.tab({ shift: true });
    expect(skip).toHaveFocus();
  });

  test("free text: Answer stays disabled until text is typed, and Enter submits", async () => {
    const { onClose, user } = await open(freeText);
    const answer = screen.getByRole("button", { name: "Answer" });
    const input = screen.getByRole("textbox", { name: "Answer: Which branch should I scan?" });
    expect(answer).toBeDisabled();

    // Whitespace alone is not an answer.
    await user.type(input, "   ");
    expect(answer).toBeDisabled();
    await user.keyboard("{Enter}");
    expect(respond).not.toHaveBeenCalled();

    await user.clear(input);
    await user.type(input, "  main  ");
    expect(answer).toBeEnabled();
    await user.keyboard("{Enter}");

    await waitFor(() => expect(onClose).toHaveBeenCalledOnce());
    expect(respond).toHaveBeenCalledExactlyOnceWith("req-1", ["main"]);
  });

  test("single select: options toggle aria-pressed and a second click deselects", async () => {
    const { user } = await open(single);
    const high = screen.getByRole("button", { name: "High" });
    const low = screen.getByRole("button", { name: "Low" });
    const answer = screen.getByRole("button", { name: "Answer" });

    expect(high).toHaveAttribute("aria-pressed", "false");
    await user.click(high);
    expect(high).toHaveAttribute("aria-pressed", "true");
    expect(answer).toBeEnabled();

    // Choosing another option replaces the first.
    await user.click(low);
    expect(high).toHaveAttribute("aria-pressed", "false");
    expect(low).toHaveAttribute("aria-pressed", "true");

    await user.click(low);
    expect(low).toHaveAttribute("aria-pressed", "false");
    expect(answer).toBeDisabled();
  });

  test("multi select accumulates choices and submits them as an array", async () => {
    const { onClose, user } = await open(multi);
    await user.click(screen.getByRole("button", { name: "npm" }));
    await user.click(screen.getByRole("button", { name: "pip" }));
    await user.click(screen.getByRole("button", { name: "cargo" }));
    // Deselecting one keeps the others.
    await user.click(screen.getByRole("button", { name: "pip" }));

    expect(screen.getByRole("button", { name: "npm" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "cargo" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "pip" })).toHaveAttribute("aria-pressed", "false");

    await user.click(screen.getByRole("button", { name: "Answer" }));
    await waitFor(() => expect(onClose).toHaveBeenCalledOnce());
    expect(respond).toHaveBeenCalledExactlyOnceWith("req-1", [["npm", "cargo"]]);
  });

  test("submits every answer in question order, then closes", async () => {
    const { onClose, user } = await open([...single, ...freeText, ...multi]);
    const answer = screen.getByRole("button", { name: "Answer" });

    // Answer in reverse order; the payload must still follow question order.
    await user.click(screen.getByRole("button", { name: "cargo" }));
    expect(answer).toBeDisabled();
    await user.type(screen.getByRole("textbox"), "release/2.0");
    expect(answer).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Low" }));
    expect(answer).toBeEnabled();

    expect(onClose).not.toHaveBeenCalled();
    await user.click(answer);

    await waitFor(() => expect(onClose).toHaveBeenCalledOnce());
    expect(respond).toHaveBeenCalledExactlyOnceWith("req-1", ["Low", "release/2.0", ["cargo"]]);
  });

  test("a failed submit shows the error and stays open; editing clears it", async () => {
    respond.mockRejectedValueOnce({
      code: "internal",
      message: "Interaction expired",
      detail: null,
      retryable: false,
    });
    const { onClose, user } = await open(freeText);
    const input = screen.getByRole("textbox");
    await user.type(input, "main");
    await user.click(screen.getByRole("button", { name: "Answer" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Interaction expired");
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    await user.type(input, "!");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  test("a failed submit on an option question is cleared by choosing again", async () => {
    respond.mockRejectedValueOnce(new Error("Backend unavailable"));
    const { onClose, user } = await open(single);
    await user.click(screen.getByRole("button", { name: "High" }));
    await user.click(screen.getByRole("button", { name: "Answer" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Backend unavailable");
    expect(onClose).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Low" }));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  test("counts down visibly from 180 seconds", async () => {
    vi.useFakeTimers();
    setup(freeText, { fakeTimers: true });
    expect(screen.getByText("180s remaining")).toBeInTheDocument();
    await act(async () => {
      vi.advanceTimersByTime(5_000);
    });
    expect(screen.getByText("175s remaining")).toBeInTheDocument();
  });

  test("skips the request when the countdown reaches zero", async () => {
    vi.useFakeTimers();
    const { onClose } = setup(freeText, { fakeTimers: true });
    await act(async () => {
      vi.advanceTimersByTime(179_000);
    });
    expect(respond).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();

    await act(async () => {
      vi.advanceTimersByTime(1_000);
    });
    expect(respond).toHaveBeenCalledExactlyOnceWith("req-1", []);
    expect(onClose).toHaveBeenCalledOnce();
  });

  test("returns focus to the previously focused element on unmount", async () => {
    const opener = document.createElement("button");
    opener.textContent = "Composer";
    document.body.appendChild(opener);
    opener.focus();

    const { onRestoreFocus, unmount } = setup(freeText);
    await waitFor(() => expect(screen.getByRole("button", { name: "Skip" })).toHaveFocus());

    unmount();
    // Restoration is deferred a frame so it lands after React commits.
    await waitFor(() => expect(opener).toHaveFocus());
    expect(onRestoreFocus).not.toHaveBeenCalled();
    opener.remove();
  });

  test("falls back to onRestoreFocus when the previously focused element is gone", async () => {
    const opener = document.createElement("button");
    document.body.appendChild(opener);
    opener.focus();

    const { onRestoreFocus, unmount } = setup(freeText);
    await waitFor(() => expect(screen.getByRole("button", { name: "Skip" })).toHaveFocus());

    opener.remove();
    unmount();
    await waitFor(() => expect(onRestoreFocus).toHaveBeenCalledOnce());
  });
});
