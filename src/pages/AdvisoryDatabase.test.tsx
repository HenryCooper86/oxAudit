import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { AdvisoryDatabasePage } from "./AdvisoryDatabase";

const listen = vi.fn().mockResolvedValue(() => {});
vi.mock("@tauri-apps/api/event", () => ({
  listen: (...args: unknown[]) => listen(...args),
}));

const advisoryDbStatus = vi.fn();
const advisoryDbUpdate = vi.fn();
const defaultAdvisoryDbPath = vi.fn();
vi.mock("../lib/api", () => ({
  api: {
    advisoryDbStatus: (...args: unknown[]) => advisoryDbStatus(...args),
    advisoryDbUpdate: (...args: unknown[]) => advisoryDbUpdate(...args),
    defaultAdvisoryDbPath: (...args: unknown[]) => defaultAdvisoryDbPath(...args),
  },
}));

const toast = vi.fn();
vi.mock("../lib/stores", () => ({
  useToastStore: (selector: (state: { push: typeof toast }) => unknown) =>
    selector({ push: toast }),
}));

const status = {
  path: "/tmp/advisories.sqlite3",
  schemaVersion: 1,
  ecosystems: ["npm", "Debian:12"],
  advisories: 1200,
  packages: 900,
  builtAtMs: 1700000000000,
  updatedAtMs: 1700000000000,
  sizeBytes: 40 * 1024 * 1024,
};

test("status shows coverage and freshness after a refresh", async () => {
  defaultAdvisoryDbPath.mockResolvedValue("/tmp/advisories.sqlite3");
  advisoryDbStatus.mockResolvedValue(status);
  render(<AdvisoryDatabasePage />);
  const pathInput = screen.getByLabelText("Advisory database path");
  await waitFor(() => expect(pathInput).toHaveValue("/tmp/advisories.sqlite3"));
  await userEvent.click(screen.getByRole("button", { name: /status/i }));
  expect(await screen.findByText(/npm, Debian:12/)).toBeInTheDocument();
  expect(screen.getByText(/1200 \/ 900/)).toBeInTheDocument();
  expect(screen.getByText(/never widens coverage/i)).toBeInTheDocument();
});

test("update downloads defaults plus the extra ecosystems named", async () => {
  defaultAdvisoryDbPath.mockResolvedValue("/tmp/advisories.sqlite3");
  advisoryDbStatus.mockResolvedValue(status);
  advisoryDbUpdate.mockResolvedValue({
    ecosystems: [{ ecosystem: "npm", records: 1000 }],
    totalAdvisories: 1200,
    totalPackages: 900,
    builtAtMs: 1,
  });
  render(<AdvisoryDatabasePage />);
  const pathInput = screen.getByLabelText("Advisory database path");
  await waitFor(() => expect(pathInput).toHaveValue("/tmp/advisories.sqlite3"));
  await userEvent.type(screen.getByLabelText("Extra ecosystems"), "Debian:12, Hex");
  await userEvent.click(screen.getByRole("button", { name: /download defaults/i }));
  await waitFor(() =>
    expect(advisoryDbUpdate).toHaveBeenCalledWith("/tmp/advisories.sqlite3", ["Debian:12", "Hex"]),
  );
  expect(await screen.findByText(/1200 advisories over 900 packages/)).toBeInTheDocument();
});
