import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, test } from "vitest";

import type { ToolRecord } from "../../lib/types";
import { ToolCallCard } from "./ToolCallCard";

function record(overrides: Partial<ToolRecord> = {}): ToolRecord {
  return {
    toolCallId: "call-1",
    name: "read_file",
    arguments: '{"path":"src/main.rs"}',
    status: "success",
    durationMs: null,
    resultPreview: "fn main() {}",
    ...overrides,
  };
}

function toggle() {
  return screen.getByRole("button", { name: /read_file/ });
}

describe("ToolCallCard", () => {
  test.each([
    ["running", "Running"],
    ["success", "Completed"],
    ["error", "Failed"],
  ] as const)("labels a %s call as %s", (status, label) => {
    render(<ToolCallCard record={record({ status })} />);
    expect(toggle()).toHaveTextContent(label);
  });

  test("shows the duration only once one is known", () => {
    const { rerender } = render(<ToolCallCard record={record({ durationMs: null })} />);
    expect(toggle()).not.toHaveTextContent(/\d+(\.\d)? (ms|s)\b/);

    rerender(<ToolCallCard record={record({ durationMs: 1500 })} />);
    expect(toggle()).toHaveTextContent("1.5 s");

    rerender(<ToolCallCard record={record({ durationMs: 0 })} />);
    expect(toggle()).toHaveTextContent("0 ms");
  });

  test("a failed call previews the start of its error without expanding", () => {
    const longError = `permission denied: ${"x".repeat(100)}`;
    render(<ToolCallCard record={record({ status: "error", resultPreview: longError })} />);
    const preview = screen.getByText(/^permission denied/);
    expect(preview).toHaveTextContent(longError.slice(0, 60));
    expect(preview.textContent).toHaveLength(60);
  });

  test("a failed call with no result still says it failed", () => {
    render(<ToolCallCard record={record({ status: "error", resultPreview: null })} />);
    expect(screen.getByText("failed")).toBeInTheDocument();
  });

  test("a successful call does not show a result preview until expanded", () => {
    render(<ToolCallCard record={record()} />);
    expect(screen.queryByText("fn main() {}")).not.toBeInTheDocument();
  });

  test("the toggle expands details it controls, with arguments and result", async () => {
    const user = userEvent.setup();
    render(<ToolCallCard record={record()} />);
    const button = toggle();
    expect(button).toHaveAttribute("aria-expanded", "false");

    await user.click(button);
    expect(button).toHaveAttribute("aria-expanded", "true");
    const details = document.getElementById(button.getAttribute("aria-controls")!);
    expect(details).not.toBeNull();
    expect(details).toHaveTextContent("Arguments");
    expect(details).toHaveTextContent('{"path":"src/main.rs"}');
    expect(details).toHaveTextContent("Result");
    expect(details).toHaveTextContent("fn main() {}");
    expect(details).not.toHaveTextContent("running…");

    await user.click(button);
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText("Arguments")).not.toBeInTheDocument();
  });

  test("details say the call is still running and omit sections with no content", async () => {
    const user = userEvent.setup();
    render(
      <ToolCallCard record={record({ status: "running", arguments: "", resultPreview: null })} />,
    );
    await user.click(toggle());
    const details = document.getElementById(toggle().getAttribute("aria-controls")!);
    expect(details).toHaveTextContent("running…");
    expect(details).not.toHaveTextContent("Arguments");
    expect(details).not.toHaveTextContent("Result");
  });

  test("updates in place when the record's status changes", () => {
    const { rerender } = render(<ToolCallCard record={record({ status: "running" })} />);
    expect(toggle()).toHaveTextContent("Running");
    rerender(<ToolCallCard record={record({ status: "success", durationMs: 250 })} />);
    expect(toggle()).toHaveTextContent("Completed");
    expect(toggle()).toHaveTextContent("250 ms");
  });
});
