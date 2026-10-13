import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../lib/api";
import type { QualityStatus } from "../lib/types";
import { QualityLabPage } from "./QualityLab";

const status: QualityStatus = {
  schemaVersion: 1, suiteId: "local", suiteVersion: "1", description: "Pinned corpus",
  corpusTargets: 1, passedTargets: 1, truePositives: 1, falsePositives: 0,
  falseNegatives: 0, precision: 1, recall: 1, runtimeMs: 1, misses: [], unexpected: [],
  limitation: "Limited corpus", previousPrecision: null, previousRecall: null, regression: false,
};

beforeEach(() => {
  vi.spyOn(api, "qualityStatus").mockResolvedValue(status);
  vi.spyOn(api, "listCompiledGrammars").mockResolvedValue(["javascript"]);
});

test("a failed grammar query is unavailable rather than claiming text-only scanning", async () => {
  vi.mocked(api.listCompiledGrammars).mockRejectedValueOnce("Grammar registry unavailable");
  render(<QualityLabPage />);
  await screen.findByText("Grammar registry unavailable");
  expect(screen.queryByText(/None — every file/)).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Retry grammars" }));
  expect(await screen.findByText("javascript")).toBeInTheDocument();
  expect(screen.queryByText("Grammar registry unavailable")).not.toBeInTheDocument();
});

test("the first benchmark reports a baseline without claiming a comparison", async () => {
  render(<QualityLabPage />);
  await screen.findByText(/first local baseline/);
  expect(screen.queryByText("No measured regression from the previous saved run")).not.toBeInTheDocument();
});
