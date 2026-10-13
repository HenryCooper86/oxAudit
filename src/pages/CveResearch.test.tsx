import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../lib/api";
import { useAppStore } from "../lib/stores";
import type { CveSearchResult } from "../lib/types";
import { CveResearchPage } from "./CveResearch";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (cause: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

beforeEach(() => useAppStore.setState({ pageStatus: {} }));

test.each(["success", "failure"])("a delayed %s cannot restore research status after leaving the page", async outcome => {
  const pending = deferred<CveSearchResult>();
  vi.spyOn(api, "searchCves").mockReturnValue(pending.promise);
  const view = render(<CveResearchPage />);
  await userEvent.click(screen.getByRole("button", { name: "Search NVD" }));
  expect(useAppStore.getState().pageStatus["cve-research"]?.tone).toBe("running");
  view.unmount();
  await act(async () => {
    if (outcome === "success") pending.resolve({ total: 0, items: [] });
    else pending.reject("NVD unavailable");
  });
  expect(useAppStore.getState().pageStatus["cve-research"]).toBeUndefined();
});
