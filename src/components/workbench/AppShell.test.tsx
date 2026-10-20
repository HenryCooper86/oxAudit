import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { useAppStore } from "../../lib/stores";
import { useScanWorkStore } from "../../features/project-home/coordinator";
import { AppShell } from "./AppShell";

beforeEach(() => {
  localStorage.clear();
  useAppStore.setState({ page: "binary-scan", settings: null });
  useScanWorkStore.setState({ active: null, recoveryError: null });
});

test("keyboard users can bypass navigation and continue into the current workspace", async () => {
  const user = userEvent.setup();
  render(<AppShell><button>Workspace action</button></AppShell>);
  await user.tab();
  expect(screen.getByRole("link", { name: "Skip to workspace" })).toHaveFocus();
  await user.keyboard("{Enter}");
  expect(screen.getByRole("main")).toHaveFocus();
  await user.tab();
  expect(screen.getByRole("button", { name: "Workspace action" })).toHaveFocus();
});

test("Escape closes navigation and returns focus to its opener", async () => {
  const user = userEvent.setup();
  render(<AppShell><button>Workspace action</button></AppShell>);
  const opener = screen.getByRole("button", { name: "Open navigation" });
  await user.click(opener);
  await waitFor(() => expect(screen.getAllByRole("button", { name: "Close navigation" })[1]).toHaveFocus());
  await user.keyboard("{Escape}");
  await waitFor(() => expect(opener).toHaveFocus());
  expect(screen.getAllByRole("button", { name: "Close navigation" })).toHaveLength(1);
  expect(screen.getByRole("main").parentElement).not.toHaveAttribute("inert");
});

test("blocked browser storage leaves navigation usable for the current session", async () => {
  vi.spyOn(window, "localStorage", "get").mockImplementation(() => {
    throw new DOMException("Storage blocked", "SecurityError");
  });
  const user = userEvent.setup();
  render(<AppShell><button>Workspace action</button></AppShell>);

  await user.click(screen.getByRole("button", { name: "Collapse navigation" }));
  expect(screen.getByRole("button", { name: "Expand navigation" })).toHaveAttribute("aria-expanded", "false");
  await user.click(screen.getByRole("button", { name: "Expand navigation" }));
  expect(screen.getByRole("button", { name: "Collapse navigation" })).toHaveAttribute("aria-expanded", "true");
  expect(screen.getByRole("button", { name: "Workspace action" })).toBeInTheDocument();
});
