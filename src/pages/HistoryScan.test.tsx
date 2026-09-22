import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { HistoryScanPage } from "./HistoryScan";
import type { Finding, HistoryScanResult } from "../lib/types";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const scanHistorySecrets = vi.fn();
vi.mock("../lib/api", () => ({
  api: { scanHistorySecrets: (...args: unknown[]) => scanHistorySecrets(...args) },
}));

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  id: "finding-1",
  category: "secret",
  ruleId: "aws-access-key-id",
  ruleName: "AWS Access Key ID",
  severity: "high",
  title: "AWS Access Key ID",
  description: "An AWS Access Key ID was found.",
  filePath: "src/deploy.sh",
  line: 2,
  column: 27,
  matchText: "export AWS_ACCESS_KEY_ID=[REDACTED]",
  context: "#!/bin/sh\nexport AWS_ACCESS_KEY_ID=[REDACTED]",
  language: "",
  cwe: null,
  cweExploited: false,
  cweExploitedCount: 0,
  recommendation: "Rotate the key.",
  entropy: 3.9,
  verified: null,
  analysis: "text",
  analysisGates: [],
  observationRunId: "",
  resolvedByRunId: null,
  fingerprintVersion: 1,
  fingerprint: "abc123",
  scope: null,
  scopeReason: null,
  review: null,
  reviewHistory: [],
  diffStatus: null,
  ...overrides,
});

const result = (overrides: Partial<HistoryScanResult> = {}): HistoryScanResult => ({
  findings: [finding()],
  blobsScanned: 412,
  blobsSkipped: 3,
  truncated: false,
  limitNote: null,
  ...overrides,
});

async function runScan(payload: HistoryScanResult) {
  scanHistorySecrets.mockResolvedValue(payload);
  render(<HistoryScanPage />);
  await userEvent.type(screen.getByRole("textbox", { name: /repository folder/i }), "/tmp/repo");
  const button = screen.getByRole("button", { name: /scan history$/i });
  await userEvent.click(button);
  await waitFor(() => expect(scanHistorySecrets).toHaveBeenCalledWith("/tmp/repo"));
  await waitFor(() => expect(button).not.toBeDisabled());
}

test("a completed history scan lists findings at their historical paths", async () => {
  await runScan(result());
  expect(await screen.findByText("aws-access-key-id")).toBeInTheDocument();
  expect(await screen.findByText("src/deploy.sh:2")).toBeInTheDocument();
  expect(screen.getByText(/1 shown · 1 historical secret/i)).toBeInTheDocument();
  // The redacted match is the evidence surface; the raw secret never exists here.
  expect(screen.getAllByText(/export AWS_ACCESS_KEY_ID=\[REDACTED\]/).length).toBeGreaterThan(0);
  expect(screen.queryByText(/stopped early/i)).not.toBeInTheDocument();
});

test("a truncated history scan says so instead of implying completeness", async () => {
  await runScan(
    result({ truncated: true, limitNote: "total scanned-bytes budget reached" }),
  );
  expect(screen.getByText("History scan stopped early")).toBeInTheDocument();
  expect(screen.getByText(/total scanned-bytes budget reached/i)).toBeInTheDocument();
  expect(screen.getByText(/findings below are partial/i)).toBeInTheDocument();
});

test("a clean history reports the blob count, not safety", async () => {
  await runScan(result({ findings: [], blobsScanned: 88 }));
  expect(screen.getByText(/no secrets in history — 88 blobs scanned/i)).toBeInTheDocument();
  expect(screen.getByText(/not proof no credential was ever typed/i)).toBeInTheDocument();
});

test("a failed scan surfaces the error with a retry", async () => {
  scanHistorySecrets.mockRejectedValue(new Error("Git history unavailable: not a git repository"));
  render(<HistoryScanPage />);
  await userEvent.type(screen.getByRole("textbox", { name: /repository folder/i }), "/tmp/repo");
  await userEvent.click(screen.getByRole("button", { name: /scan history$/i }));
  expect(await screen.findByText("History scan failed")).toBeInTheDocument();
  expect(screen.getByText(/not a git repository/i)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
});
