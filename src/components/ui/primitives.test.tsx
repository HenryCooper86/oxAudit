import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Bug } from "lucide-react";
import { useState } from "react";
import { expect, test } from "vitest";
import { InlineState } from "../workbench/InlineState";
import { ToolPage } from "../workbench/ToolPage";
import { listRowClassName } from "../workbench/listRow";
import { Button, Checkbox, Input, MetricGrid, MetricTile, SearchField, Select, SettingsGroup, SettingsItem, Switch } from ".";

test("SettingsGroup titles a bordered card of rows, labelled for assistive tech", () => {
  render(
    <SettingsGroup title="Appearance" description="Applies to this window.">
      <SettingsItem title="Theme" description="Dark, light or follow the system.">
        <Button>Dark</Button>
      </SettingsItem>
      <SettingsItem title="Endpoint" htmlFor="endpoint" stacked>
        <Input id="endpoint" />
      </SettingsItem>
    </SettingsGroup>,
  );
  const group = screen.getByRole("region", { name: "Appearance" });
  expect(within(group).getByText("Applies to this window.")).toBeInTheDocument();
  expect(within(group).getByRole("button", { name: "Dark" })).toBeInTheDocument();
  // A stacked row labels its control and gives it the full width.
  const field = within(group).getByRole("textbox", { name: "Endpoint" });
  expect(field.parentElement).toHaveClass("w-full");
  const rows = group.querySelectorAll(".min-h-11");
  expect(rows).toHaveLength(2);
});

test("MetricTile shows a label and value and marks counts that need attention", () => {
  render(
    <>
      <MetricTile icon={<Bug size={16} />} label="Critical" value={3} detail="2 new" attention />
      <MetricTile icon={<Bug size={16} />} label="Open" value="unknown" />
    </>,
  );
  const critical = screen.getByText("Critical").closest(".surface-card") as HTMLElement;
  expect(critical).toHaveTextContent("Critical32 new");
  expect(critical.querySelector("[aria-hidden='true']")).toHaveClass("text-error");
  const open = screen.getByText("Open").closest(".surface-card") as HTMLElement;
  expect(open).toHaveTextContent("unknown");
  expect(open.querySelector("[aria-hidden='true']")).toHaveClass("text-accent");
});

test("InlineState draws empty and idle states as a centred card, notices with a status stripe", () => {
  const view = render(<InlineState tone="empty" title="No findings in this view" description="Zero findings is not a safety claim." />);
  const empty = screen.getByRole("status");
  expect(empty).toHaveClass("surface-card", "text-center");
  expect(empty.querySelector(".rounded-full")).not.toBeNull();

  view.rerender(<InlineState tone="error" title="Saved results unavailable" />);
  const error = screen.getByRole("alert");
  expect(error).toHaveClass("surface-card", "border-l-[3px]", "border-l-error");

  view.rerender(<InlineState tone="empty" compact title="Select an advisory" />);
  expect(screen.getByRole("status")).toHaveClass("border-l-[3px]");

  view.rerender(<InlineState tone="running" title="Scanning" progress={<progress aria-label="Scan progress" />} />);
  expect(screen.queryByRole("status")).not.toBeInTheDocument();
  expect(screen.getByRole("progressbar", { name: "Scan progress" })).toBeInTheDocument();
});

test("Switch is a labelled switch that reports its new state", async () => {
  function Harness() {
    const [on, setOn] = useState(false);
    return <Switch checked={on} onChange={setOn} label="Offline mode" />;
  }
  render(<Harness />);
  const control = screen.getByRole("switch", { name: "Offline mode" });
  expect(control).not.toBeChecked();
  await userEvent.click(control);
  expect(control).toBeChecked();
});

test("Button keeps oxAudit's extra variants on oxFuzz's 8px radius and heights", () => {
  render(
    <>
      <Button variant="primary">Run scan</Button>
      <Button variant="accent" size="sm">Discuss</Button>
      <Button variant="danger">Delete</Button>
      <Button variant="warning">Accept risk</Button>
    </>,
  );
  expect(screen.getByRole("button", { name: "Run scan" })).toHaveClass("rounded-md", "h-8", "bg-accent");
  expect(screen.getByRole("button", { name: "Discuss" })).toHaveClass("h-7", "bg-accent-subtle");
  expect(screen.getByRole("button", { name: "Delete" })).toHaveClass("text-error");
  expect(screen.getByRole("button", { name: "Accept risk" })).toHaveClass("text-warning");
});

test("ToolPage renders the page's single h1 with its description and actions", () => {
  render(
    <ToolPage title="Inventory" description="Components across saved runs." actions={<Button>Refresh</Button>}>
      <p>Body</p>
    </ToolPage>,
  );
  expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
  expect(screen.getByRole("heading", { level: 1, name: "Inventory" })).toBeInTheDocument();
  expect(screen.getByText("Components across saved runs.")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
});

test("list rows are card buttons; the selected row moves to the focus border", () => {
  expect(listRowClassName(true)).toMatch(/\bborder-border-focus\b/);
  expect(listRowClassName(false)).toMatch(/\bborder-border\b/);
  expect(listRowClassName(false)).toMatch(/\brounded-md\b/);
});

test("SettingsItem ties its description and error to the control it labels", () => {
  render(
    <SettingsGroup title="Limits">
      <SettingsItem title="Timeout" description="One request, 1 to 120 seconds." htmlFor="timeout" error="Enter a whole number.">
        <Input id="timeout" />
      </SettingsItem>
    </SettingsGroup>,
  );
  const field = screen.getByLabelText("Timeout");
  expect(field).toHaveAttribute("aria-invalid", "true");
  expect(field).toHaveAccessibleDescription("One request, 1 to 120 seconds. Enter a whole number.");
  expect(screen.getByRole("alert")).toHaveTextContent("Enter a whole number.");
});

test("Checkbox and SearchField keep native roles and accessible names", async () => {
  const user = userEvent.setup();
  const Harness = () => {
    const [on, setOn] = useState(false);
    return (
      <>
        <Checkbox checked={on} onChange={(event) => setOn(event.target.checked)}>New since baseline</Checkbox>
        <SearchField aria-label="Search findings" placeholder="Search findings…" />
      </>
    );
  };
  render(<Harness />);
  const box = screen.getByRole("checkbox", { name: "New since baseline" });
  await user.click(box);
  expect(box).toBeChecked();
  const search = screen.getByRole("textbox", { name: "Search findings" });
  expect(search).toHaveClass("h-7", "rounded-md");
  await user.type(search, "eval");
  expect(search).toHaveValue("eval");
});

test("MetricGrid is a labelled region whose tiles expose label and value as text", () => {
  render(
    <MetricGrid label="Scan summary">
      <MetricTile icon={<Bug size={16} />} label="Files" value="4" />
      <MetricTile icon={<Bug size={16} />} label="Critical / High" value="0 / 5" attention />
    </MetricGrid>,
  );
  const region = screen.getByRole("region", { name: "Scan summary" });
  expect(within(region).getByText("Files")).toBeInTheDocument();
  expect(within(region).getByText("4")).toBeInTheDocument();
  expect(within(region).getByText("0 / 5")).toBeInTheDocument();
});

test("Select stays a native select, hides the system arrow and sizes through its wrapper", async () => {
  const user = userEvent.setup();
  const { container } = render(
    <>
      <Select aria-label="Editor" className="mt-1 w-60 text-text-primary" defaultValue="a">
        <option value="a">One</option>
        <option value="b">Two</option>
      </Select>
      <Select aria-label="Sort" variant="compact" defaultValue="a">
        <option value="a">One</option>
      </Select>
    </>,
  );
  const field = screen.getByRole("combobox", { name: "Editor" });
  expect(field.tagName).toBe("SELECT");
  expect(field).toHaveClass("appearance-none", "h-9", "pr-8", "text-text-primary");
  expect(field).not.toHaveClass("w-60");
  const wrapper = field.parentElement as HTMLElement;
  expect(wrapper).toHaveClass("w-60", "mt-1", "relative");
  expect(wrapper).not.toHaveClass("w-full");
  expect(wrapper.querySelector("svg[aria-hidden='true']")).toHaveClass("pointer-events-none");
  expect(screen.getByRole("combobox", { name: "Sort" })).toHaveClass("h-7", "appearance-none");
  expect(container.querySelectorAll("select")).toHaveLength(2);
  await user.selectOptions(field, "b");
  expect(field).toHaveValue("b");
});
