import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { VexTrustPage } from "./VexTrust";

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

test("trust without a name is refused rather than recorded anonymously", async () => {
  vexClaimSets.mockResolvedValue([claimSet]);
  listCanonicalRuns.mockResolvedValue([]);
  render(<VexTrustPage />);
  await screen.findByText(/untrusted/);
  await userEvent.click(screen.getByRole("button", { name: /trust this document/i }));
  expect(vexGrantTrust).not.toHaveBeenCalled();
  expect(toast).toHaveBeenCalledWith("error", expect.stringContaining("who made them"));
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
