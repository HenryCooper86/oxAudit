import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { api } from "../lib/api";
import { DataSourcesPage } from "./DataSources";
import * as opener from "../lib/opener";
import { useToastStore } from "../lib/stores";
import type { DataSourceStatus } from "../lib/types";

test("a failed registry load can be retried without leaving the workspace", async () => {
  vi.spyOn(api, "listDataSources").mockRejectedValueOnce("Provider registry unavailable").mockResolvedValue([]);
  render(<DataSourcesPage />);
  await screen.findByText("Provider registry unavailable");
  await userEvent.click(screen.getByRole("button", { name: "Retry registry" }));
  expect(await screen.findByText("No data sources are registered")).toBeInTheDocument();
  expect(screen.queryByText("Provider registry unavailable")).not.toBeInTheDocument();
});

test("a failed provenance link reports the opener failure", async () => {
  const source: DataSourceStatus = {
    id: "provider", name: "Provider", sourceUrl: "https://example.com/data", termsUrl: "https://example.com/terms",
    license: "Public", state: "notRefreshed", supportsOffline: false, activeSnapshotId: null,
    fetchedAtMs: null, contentSha256: null, recordCount: null, validation: "Not checked", limitation: "Online only",
  };
  vi.spyOn(api, "listDataSources").mockResolvedValue([source]);
  vi.spyOn(opener, "openUrl").mockRejectedValue("No URL handler");
  useToastStore.setState({ toasts: [] });
  render(<DataSourcesPage />);
  await userEvent.click(await screen.findByRole("button", { name: "Terms & provenance" }));
  expect(useToastStore.getState().toasts.some(toast => toast.kind === "error" && toast.message.includes("could not be opened"))).toBe(true);
});
