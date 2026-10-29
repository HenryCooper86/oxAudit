import { render, screen, within } from "@testing-library/react";
import { describe, expect, test } from "vitest";

import type { TodoItem, ToolRecord, UsageSummary } from "../../lib/types";
import { AssistantActivityPanel } from "./AssistantActivityPanel";

function tool(index: number, status: ToolRecord["status"] = "success"): ToolRecord {
  return {
    toolCallId: `call-${index}`,
    name: `tool_${index}`,
    arguments: "{}",
    status,
    durationMs: null,
    resultPreview: null,
  };
}

const usage: UsageSummary = {
  turns: 2,
  promptTokens: 1000,
  completionTokens: 234,
  totalTokens: 1234,
  costUsd: 0.01234,
};

function renderPanel(props: Partial<Parameters<typeof AssistantActivityPanel>[0]> = {}) {
  render(
    <AssistantActivityPanel
      busy={false}
      model={null}
      tools={[]}
      todos={[]}
      usage={null}
      {...props}
    />,
  );
  return screen.getByRole("complementary", { name: "Assistant activity" });
}

/** The value printed directly above a stat caption such as "tools". */
function stat(panel: HTMLElement, caption: string): string | null {
  const label = within(panel).getByText(caption, { selector: "div" });
  return label.previousElementSibling?.textContent ?? null;
}

describe("AssistantActivityPanel", () => {
  test("labels itself Idle when the assistant is not working", () => {
    const panel = renderPanel({ busy: false });
    expect(within(panel).getByText("Idle")).toBeInTheDocument();
    expect(within(panel).queryByText("Running")).not.toBeInTheDocument();
  });

  test("labels itself Running while the assistant works", () => {
    const panel = renderPanel({ busy: true });
    expect(within(panel).getByText("Running")).toBeInTheDocument();
    expect(within(panel).queryByText("Idle")).not.toBeInTheDocument();
  });

  test("shows zero tools and 0/0 ok before any calls", () => {
    const empty = renderPanel();
    expect(stat(empty, "tools")).toBe("0");
    expect(stat(empty, "ok")).toBe("0/0");
  });

  test("counts only successful tools as ok", () => {
    const panel = renderPanel({
      tools: [tool(1), tool(2, "error"), tool(3, "running"), tool(4)],
    });
    expect(stat(panel, "tools")).toBe("4");
    expect(stat(panel, "ok")).toBe("2/4");
  });

  test("shows a dash for tokens before any usage", () => {
    const panel = renderPanel();
    expect(stat(panel, "tokens")).toBe("—");
  });

  test("formats token usage in thousands", () => {
    const panel = renderPanel({ usage });
    expect(stat(panel, "tokens")).toBe("1.2k");
  });

  test("explains the empty plan", () => {
    const empty = renderPanel();
    expect(within(empty).getByText(/plan will appear here/)).toBeInTheDocument();
    expect(within(empty).queryByRole("region", { name: "Agent plan" })).not.toBeInTheDocument();
  });

  test("renders the agent plan when todos exist", () => {
    const todos: TodoItem[] = [
      { id: 1, text: "Audit lockfile", status: "done" },
      { id: 2, text: "Write report", status: "pending" },
    ];
    const panel = renderPanel({ todos });
    expect(within(panel).queryByText(/plan will appear here/)).not.toBeInTheDocument();
    const plan = within(panel).getByRole("region", { name: "Agent plan" });
    expect(plan).toHaveTextContent("1/2");
    expect(plan).toHaveTextContent("Audit lockfile");
  });

  test("explains the empty tool list", () => {
    const panel = renderPanel();
    expect(within(panel).getByText(/Tool activity will be listed here/)).toBeInTheDocument();
  });

  test("lists only the eight most recent tool calls", () => {
    const tools = Array.from({ length: 10 }, (_, index) => tool(index + 1));
    const panel = renderPanel({ tools });
    expect(within(panel).queryByText(/Tool activity will be listed here/)).not.toBeInTheDocument();
    const names = within(panel)
      .getAllByRole("button", { expanded: false })
      .map((button) => button.textContent?.match(/tool_\d+/)?.[0]);
    expect(names).toEqual([
      "tool_3", "tool_4", "tool_5", "tool_6", "tool_7", "tool_8", "tool_9", "tool_10",
    ]);
    // The total still counts every call, not just the visible ones.
    expect(stat(panel, "tools")).toBe("10");
  });

  test("says when no model is selected", () => {
    const panel = renderPanel({ model: null });
    expect(within(panel).getByText("Model not selected")).toBeInTheDocument();
  });

  test("shows the selected model name", () => {
    const panel = renderPanel({ model: "gpt-oss-120b" });
    expect(within(panel).getByText("gpt-oss-120b")).toBeInTheDocument();
    expect(within(panel).queryByText("Model not selected")).not.toBeInTheDocument();
  });

  test("omits cost until there is usage", () => {
    const without = renderPanel();
    expect(within(without).queryByText(/^\$/)).not.toBeInTheDocument();
  });

  test("formats cost to four decimal places", () => {
    const panel = renderPanel({ usage });
    expect(within(panel).getByText("$0.0123")).toBeInTheDocument();
  });
});
