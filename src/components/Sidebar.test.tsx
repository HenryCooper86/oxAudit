import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { Sidebar } from "./Sidebar";
import { useAppStore } from "../lib/stores";

test("YARA Scan and Template Scan are in the Scanning group and navigate", async () => {
  const onClose = vi.fn();
  render(<Sidebar open onClose={onClose} onToggleCompact={() => {}} />);
  await userEvent.click(screen.getByRole("button", { name: "YARA Scan" }));
  expect(useAppStore.getState().page).toBe("yara-scan");
  await userEvent.click(screen.getByRole("button", { name: "Template Scan" }));
  expect(useAppStore.getState().page).toBe("template-scan");
  expect(onClose).toHaveBeenCalledTimes(2);
});
