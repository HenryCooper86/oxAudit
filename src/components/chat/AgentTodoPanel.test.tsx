import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, test } from "vitest";

import type { TodoItem } from "../../lib/types";
import { AgentTodoPanel } from "./AgentTodoPanel";

const inProgress: TodoItem[] = [
  { id: 1, text: "Run the dependency audit", status: "done" },
  { id: 2, text: "Triage critical findings", status: "pending" },
  { id: 3, text: "Draft the summary", status: "pending" },
];

const finished: TodoItem[] = inProgress.map((item) => ({ ...item, status: "done" }));

describe("AgentTodoPanel", () => {
  test("renders nothing when there is no plan", () => {
    const { container } = render(<AgentTodoPanel items={[]} />);
    expect(container).toBeEmptyDOMElement();
    expect(screen.queryByRole("region", { name: "Agent plan" })).not.toBeInTheDocument();
  });

  test("shows an active plan with its done/total count and every step", () => {
    render(<AgentTodoPanel items={inProgress} />);
    const region = screen.getByRole("region", { name: "Agent plan" });
    const toggle = within(region).getByRole("button");
    expect(toggle).toHaveTextContent("Active plan");
    expect(toggle).toHaveTextContent("1/3");

    const steps = within(region).getAllByRole("listitem");
    expect(steps.map((step) => step.textContent)).toEqual([
      "Run the dependency audit",
      "Triage critical findings",
      "Draft the summary",
    ]);
  });

  test("says the plan is completed once every step is done", () => {
    render(<AgentTodoPanel items={finished} compact />);
    const toggle = screen.getByRole("button");
    expect(toggle).toHaveTextContent("Plan completed");
    expect(toggle).toHaveTextContent("3/3");
    expect(toggle).not.toHaveTextContent("Active plan");
  });

  test("collapses and expands the step list while keeping the count visible", async () => {
    const user = userEvent.setup();
    render(<AgentTodoPanel items={inProgress} />);
    const toggle = screen.getByRole("button", { name: /Active plan/ });
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("list")).toBeInTheDocument();

    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("list")).not.toBeInTheDocument();
    expect(toggle).toHaveTextContent("1/3");

    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
  });
});
