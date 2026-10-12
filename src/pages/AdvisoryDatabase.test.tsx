import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
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

const updateReport = {
  ecosystems: [{ ecosystem: "npm", records: 1000 }],
  totalAdvisories: 1200,
  totalPackages: 900,
  builtAtMs: 1,
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

beforeEach(() => {
  listen.mockReset().mockResolvedValue(() => {});
  advisoryDbStatus.mockReset();
  advisoryDbUpdate.mockReset();
  defaultAdvisoryDbPath.mockReset().mockResolvedValue("/tmp/advisories.sqlite3");
  toast.mockReset();
});

test("releases a progress subscription that finishes registering after unmount", async () => {
  const registration = deferred<() => void>();
  const subscriptions = new Set(["advisorydb://progress"]);
  listen.mockReturnValue(registration.promise);
  const { unmount } = render(<AdvisoryDatabasePage />);
  unmount();

  await act(async () => registration.resolve(() => subscriptions.clear()));

  expect(subscriptions.size).toBe(0);
});

test("reports unavailable progress without preventing database status reads", async () => {
  listen.mockRejectedValue(new Error("event bridge unavailable"));
  advisoryDbStatus.mockResolvedValue(status);
  render(<AdvisoryDatabasePage />);

  await waitFor(() => expect(toast).toHaveBeenCalledWith("error", expect.stringMatching(/progress.*event bridge unavailable/i)));
  await userEvent.click(screen.getByRole("button", { name: /status/i }));
  expect(await screen.findByText("1200 / 900")).toBeInTheDocument();
});

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

test.each(["success", "error"])("ignores a pending status %s after the database path changes", async (outcome) => {
  const request = deferred<typeof status>();
  advisoryDbStatus.mockReturnValue(request.promise);
  render(<AdvisoryDatabasePage />);
  const pathInput = screen.getByLabelText("Advisory database path");
  await waitFor(() => expect(pathInput).toHaveValue("/tmp/advisories.sqlite3"));
  await userEvent.click(screen.getByRole("button", { name: /status/i }));

  fireEvent.change(pathInput, { target: { value: "/tmp/other.sqlite3" } });
  await act(async () => {
    if (outcome === "success") request.resolve(status);
    else request.reject(new Error("original database unavailable"));
  });

  expect(screen.queryByText("1200 / 900")).not.toBeInTheDocument();
  expect(screen.queryByText(/original database unavailable/)).not.toBeInTheDocument();
});

test("a path round trip does not restore ownership of an earlier status request", async () => {
  const request = deferred<typeof status>();
  advisoryDbStatus.mockReturnValue(request.promise);
  render(<AdvisoryDatabasePage />);
  const pathInput = screen.getByLabelText("Advisory database path");
  await waitFor(() => expect(pathInput).toHaveValue("/tmp/advisories.sqlite3"));
  await userEvent.click(screen.getByRole("button", { name: /status/i }));

  fireEvent.change(pathInput, { target: { value: "/tmp/other.sqlite3" } });
  fireEvent.change(pathInput, { target: { value: "/tmp/advisories.sqlite3" } });
  await act(async () => request.resolve(status));

  expect(screen.queryByText("1200 / 900")).not.toBeInTheDocument();
});

test("a new database status request can run without waiting for the old one", async () => {
  const originalRequest = deferred<typeof status>();
  const replacementRequest = deferred<typeof status>();
  advisoryDbStatus.mockReturnValueOnce(originalRequest.promise).mockReturnValueOnce(replacementRequest.promise);
  render(<AdvisoryDatabasePage />);
  const pathInput = screen.getByLabelText("Advisory database path");
  const statusButton = screen.getByRole("button", { name: /status/i });
  await waitFor(() => expect(pathInput).toHaveValue("/tmp/advisories.sqlite3"));
  await userEvent.click(statusButton);

  fireEvent.change(pathInput, { target: { value: "/tmp/other.sqlite3" } });
  expect(statusButton).toBeEnabled();
  await userEvent.click(statusButton);
  expect(advisoryDbStatus).toHaveBeenLastCalledWith("/tmp/other.sqlite3");
  await act(async () => originalRequest.resolve(status));
  expect(statusButton).toBeDisabled();
  expect(screen.queryByText("1200 / 900")).not.toBeInTheDocument();

  await act(async () => replacementRequest.resolve({ ...status, path: "/tmp/other.sqlite3", advisories: 60, packages: 40 }));
  expect(screen.getByText("60 / 40")).toBeInTheDocument();
  expect(statusButton).toBeEnabled();
});

test("changing database clears the loaded status and update report", async () => {
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
  await userEvent.click(screen.getByRole("button", { name: /download defaults/i }));
  await screen.findByText("1200 / 900");
  expect(screen.getByText(/1200 advisories over 900 packages/)).toBeInTheDocument();

  fireEvent.change(pathInput, { target: { value: "/tmp/other.sqlite3" } });

  expect(screen.queryByText("1200 / 900")).not.toBeInTheDocument();
  expect(screen.queryByText(/1200 advisories over 900 packages/)).not.toBeInTheDocument();
});

test("changing database clears a loaded status error", async () => {
  advisoryDbStatus.mockRejectedValue(new Error("original database unavailable"));
  render(<AdvisoryDatabasePage />);
  const pathInput = screen.getByLabelText("Advisory database path");
  await waitFor(() => expect(pathInput).toHaveValue("/tmp/advisories.sqlite3"));
  await userEvent.click(screen.getByRole("button", { name: /status/i }));
  await screen.findByText(/original database unavailable/);

  fireEvent.change(pathInput, { target: { value: "/tmp/other.sqlite3" } });

  expect(screen.queryByText(/original database unavailable/)).not.toBeInTheDocument();
});

test("an active database update keeps its selected path until completion", async () => {
  const request = deferred<typeof updateReport>();
  advisoryDbUpdate.mockReturnValue(request.promise);
  advisoryDbStatus.mockResolvedValue(status);
  render(<AdvisoryDatabasePage />);
  const pathInput = screen.getByLabelText("Advisory database path");
  await waitFor(() => expect(pathInput).toHaveValue("/tmp/advisories.sqlite3"));
  await userEvent.click(screen.getByRole("button", { name: /download defaults/i }));

  await userEvent.type(pathInput, "other");
  expect(pathInput).toHaveValue("/tmp/advisories.sqlite3");
  await act(async () => request.resolve(updateReport));
  expect(await screen.findByText("1200 / 900")).toBeInTheDocument();
  expect(pathInput).toBeEnabled();
});

test("a successful database update remains successful when the status refresh fails", async () => {
  advisoryDbStatus.mockResolvedValueOnce(status).mockRejectedValueOnce(new Error("status read unavailable"));
  advisoryDbUpdate.mockResolvedValue(updateReport);
  render(<AdvisoryDatabasePage />);
  const pathInput = screen.getByLabelText("Advisory database path");
  await waitFor(() => expect(pathInput).toHaveValue("/tmp/advisories.sqlite3"));
  await userEvent.click(screen.getByRole("button", { name: /status/i }));
  await screen.findByText("1200 / 900");

  await userEvent.click(screen.getByRole("button", { name: /download defaults/i }));

  expect(await screen.findByText(/1200 advisories over 900 packages/)).toBeInTheDocument();
  expect(toast).toHaveBeenCalledWith("success", expect.stringMatching(/database updated/));
  expect(toast).not.toHaveBeenCalledWith("error", expect.stringMatching(/database update failed/));
  expect(screen.getByText(/status read unavailable/)).toBeInTheDocument();
  expect(screen.queryByText("1200 / 900")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /download defaults/i })).toBeEnabled();
});

test("starting a database update clears a previous status error", async () => {
  const request = deferred<typeof updateReport>();
  advisoryDbStatus.mockRejectedValueOnce(new Error("old status read unavailable")).mockResolvedValueOnce(status);
  advisoryDbUpdate.mockReturnValue(request.promise);
  render(<AdvisoryDatabasePage />);
  const pathInput = screen.getByLabelText("Advisory database path");
  await waitFor(() => expect(pathInput).toHaveValue("/tmp/advisories.sqlite3"));
  await userEvent.click(screen.getByRole("button", { name: /status/i }));
  await screen.findByText(/old status read unavailable/);

  await userEvent.click(screen.getByRole("button", { name: /download defaults/i }));

  expect(screen.queryByText(/old status read unavailable/)).not.toBeInTheDocument();
  await act(async () => request.resolve(updateReport));
});
