import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { VexTrustPage } from "./VexTrust";
import type { VexSuggestions } from "../lib/types";

beforeEach(() => {
  vi.clearAllMocks();
});

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

const vexClaimSets = vi.fn();
const vexGrantTrust = vi.fn();
const vexRevokeTrust = vi.fn();
const vexSuggest = vi.fn();
const listCanonicalRuns = vi.fn();
vi.mock("../lib/api", () => ({
  api: {
    vexClaimSets: (...args: unknown[]) => vexClaimSets(...args),
    vexGrantTrust: (...args: unknown[]) => vexGrantTrust(...args),
    vexRevokeTrust: (...args: unknown[]) => vexRevokeTrust(...args),
    vexSuggest: (...args: unknown[]) => vexSuggest(...args),
    listCanonicalRuns: (...args: unknown[]) => listCanonicalRuns(...args),
  },
}));

const toast = vi.fn();
vi.mock("../lib/stores", () => ({
  useToastStore: (selector: (state: { push: typeof toast }) => unknown) =>
    selector({ push: toast }),
}));

const claimSet = {
  runId: "run-import-1",
  contentSha256: "a".repeat(64),
  format: "openvex",
  claims: 2,
  trusted: false,
  grantedBy: null,
  grantedAtMs: null,
};

const run = {
  id: "run-deps-1",
  kind: "dependencies" as const,
  targetLabel: "/repo",
  state: "completed" as const,
  attempt: 1,
  createdAtMs: 1,
  updatedAtMs: 1,
  engineIds: [],
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

const suggestions: VexSuggestions = {
  suggestions: [{
    advisoryId: "GHSA-stale", ecosystem: "npm", packageName: "left-pad",
    installedVersion: "1.3.0", status: "not_affected",
    justification: "vulnerable_code_not_present", documentSha256: "a".repeat(64),
    grantedBy: "henry",
  }],
  unmapped: [], untrusted: [], runTarget: "/repo",
};

test("changing dependency runs clears completed suggestions", async () => {
  vexClaimSets.mockResolvedValue([]);
  listCanonicalRuns.mockResolvedValue([run, { ...run, id: "run-deps-2", targetLabel: "/other" }]);
  vexSuggest.mockResolvedValue(suggestions);
  render(<VexTrustPage />);
  await screen.findByRole("option", { name: /\/repo/ });
  await userEvent.selectOptions(screen.getByLabelText("Dependency run"), run.id);
  await userEvent.click(screen.getByRole("button", { name: "Suggest" }));
  await screen.findByText(/GHSA-stale/);
  await userEvent.selectOptions(screen.getByLabelText("Dependency run"), "run-deps-2");
  expect(screen.queryByText(/GHSA-stale/)).not.toBeInTheDocument();
});

test.each(["success", "failure"])("a late suggestion %s cannot leak across an A to B to A selection", async outcome => {
  const pending = deferred<VexSuggestions>();
  vexClaimSets.mockResolvedValue([]);
  listCanonicalRuns.mockResolvedValue([run, { ...run, id: "run-deps-2", targetLabel: "/other" }]);
  vexSuggest.mockReturnValue(pending.promise);
  render(<VexTrustPage />);
  await screen.findByRole("option", { name: /\/repo/ });
  await userEvent.selectOptions(screen.getByLabelText("Dependency run"), run.id);
  await userEvent.click(screen.getByRole("button", { name: "Suggest" }));
  await userEvent.selectOptions(screen.getByLabelText("Dependency run"), "run-deps-2");
  await userEvent.selectOptions(screen.getByLabelText("Dependency run"), run.id);
  await act(async () => {
    if (outcome === "success") pending.resolve(suggestions);
    else pending.reject("Old run request failed");
  });
  expect(screen.queryByText(/GHSA-stale|Old run request failed/)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Suggest" })).toBeEnabled();
});

test("revoking trust clears suggestions derived from that trust", async () => {
  vexClaimSets.mockResolvedValue([{ ...claimSet, trusted: true, grantedBy: "henry" }]);
  listCanonicalRuns.mockResolvedValue([run]);
  vexSuggest.mockResolvedValue(suggestions);
  vexRevokeTrust.mockResolvedValue(undefined);
  render(<VexTrustPage />);
  await screen.findByRole("option", { name: /\/repo/ });
  await userEvent.selectOptions(screen.getByLabelText("Dependency run"), run.id);
  await userEvent.click(screen.getByRole("button", { name: "Suggest" }));
  await screen.findByText(/GHSA-stale/);
  await userEvent.click(screen.getByRole("button", { name: "Revoke trust" }));
  await waitFor(() => expect(vexRevokeTrust).toHaveBeenCalled());
  expect(screen.queryByText(/GHSA-stale/)).not.toBeInTheDocument();
});

test("trust changes cannot overlap each other or suggestion reads", async () => {
  const pending = deferred<void>();
  vexClaimSets.mockResolvedValue([claimSet, { ...claimSet, contentSha256: "b".repeat(64) }]);
  listCanonicalRuns.mockResolvedValue([run]);
  vexGrantTrust.mockReturnValue(pending.promise);
  render(<VexTrustPage />);
  await screen.findAllByText("untrusted");
  await userEvent.type(screen.getByLabelText("Granted by"), "henry");
  await userEvent.selectOptions(screen.getByLabelText("Dependency run"), run.id);
  await userEvent.click(screen.getAllByRole("button", { name: "Trust this document" })[0]);
  for (const button of screen.getAllByRole("button", { name: "Trust this document" })) {
    expect(button).toBeDisabled();
  }
  expect(screen.getByRole("button", { name: "Suggest" })).toBeDisabled();
  await act(async () => pending.resolve());
  expect(screen.getByRole("button", { name: "Suggest" })).toBeEnabled();
});

test("retrying suggestions removes the previous error when it succeeds", async () => {
  vexClaimSets.mockResolvedValue([]);
  listCanonicalRuns.mockResolvedValue([run]);
  vexSuggest.mockRejectedValueOnce({ code: "notFound", message: "Run unavailable", detail: null, retryable: false })
    .mockResolvedValue(suggestions);
  render(<VexTrustPage />);
  await screen.findByRole("option", { name: /\/repo/ });
  await userEvent.selectOptions(screen.getByLabelText("Dependency run"), run.id);
  await userEvent.click(screen.getByRole("button", { name: "Suggest" }));
  expect(await screen.findByText("Run unavailable")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Suggest" }));
  await screen.findByText(/GHSA-stale/);
  expect(screen.queryByText("Run unavailable")).not.toBeInTheDocument();
});

test("a failed claim load ends loading and can recover without leaving the page", async () => {
  vexClaimSets.mockRejectedValueOnce("Claim database unavailable").mockResolvedValue([claimSet]);
  listCanonicalRuns.mockResolvedValue([]);
  render(<VexTrustPage />);
  await screen.findByText("Claim database unavailable");
  expect(screen.queryByText("Loading claim documents…")).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Retry claim documents" }));
  await screen.findByText("untrusted");
  expect(screen.queryByText("Claim database unavailable")).not.toBeInTheDocument();
});

test("claim documents list with trust state, and trust records who granted it", async () => {
  vexClaimSets.mockResolvedValue([claimSet]);
  listCanonicalRuns.mockResolvedValue([run]);
  vexGrantTrust.mockResolvedValue(undefined);
  render(<VexTrustPage />);

  expect(await screen.findByText(/untrusted/)).toBeInTheDocument();
  expect(screen.getByText(/2 claim\(s\)/)).toBeInTheDocument();

  await userEvent.type(screen.getByLabelText("Granted by"), "henry");
  await userEvent.click(screen.getByRole("button", { name: /trust this document/i }));
  await waitFor(() => expect(vexGrantTrust).toHaveBeenCalledWith("a".repeat(64), "henry", undefined));
  expect(screen.getByText(/name-only claim applies to nothing/i)).toBeInTheDocument();
});

test("trust without a name is disabled with an inline reason rather than recorded anonymously", async () => {
  vexClaimSets.mockResolvedValue([claimSet]);
  listCanonicalRuns.mockResolvedValue([]);
  render(<VexTrustPage />);
  await screen.findByText(/untrusted/);
  const trust = screen.getByRole("button", { name: /trust this document/i });
  expect(trust).toBeDisabled();
  expect(screen.getByText(/Enter who grants trust/)).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Granted by"), "henry");
  expect(trust).toBeEnabled();
  expect(vexGrantTrust).not.toHaveBeenCalled();
  expect(toast).not.toHaveBeenCalled();
});

test("suggestions state that they are not decisions", async () => {
  vexClaimSets.mockResolvedValue([{ ...claimSet, trusted: true, grantedBy: "henry" }]);
  listCanonicalRuns.mockResolvedValue([run]);
  vexSuggest.mockResolvedValue({
    suggestions: [
      {
        advisoryId: "GHSA-x",
        ecosystem: "npm",
        packageName: "left-pad",
        installedVersion: "1.3.0",
        status: "not_affected",
        justification: "vulnerable_code_not_present",
        documentSha256: "a".repeat(64),
        grantedBy: "henry",
      },
    ],
    unmapped: [["b".repeat(64), "record-1", "no local vulnerability with this advisory and exact package identity"]],
    untrusted: [["c".repeat(64), 3]],
    runTarget: "/repo",
  });
  render(<VexTrustPage />);
  await screen.findByText(/TRUSTED · henry/);
  await userEvent.selectOptions(screen.getByLabelText("Dependency run"), "run-deps-1");
  await userEvent.click(screen.getByRole("button", { name: /suggest/i }));
  expect(await screen.findByText(/GHSA-x/)).toBeInTheDocument();
  expect(screen.getByText(/A suggestion, not a decision/i)).toBeInTheDocument();
  expect(screen.getByText(/unmapped:/)).toBeInTheDocument();
  expect(screen.getAllByText(/untrusted document/).length).toBeGreaterThan(0);
});
