import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../lib/api";
import type { CanonicalFinding, VerificationRecord } from "../lib/types";
import { VerificationPage } from "./Verification";
import { useVerificationWrites } from "../features/verification/writes";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

const claim = (id: string): CanonicalFinding => ({
  id, runId: `run-${id}`, fingerprint: id, fingerprintVersion: 1,
  title: `Claim ${id}`, severity: "high", state: "candidate",
  classifications: [], observationIds: [], evidenceIds: [],
});
const record = (findingId: string, id = findingId): VerificationRecord => ({
  id, findingId, producerId: "scanner", verifier: { kind: "human", id: `reviewer-${id}`, version: "1" },
  inputSnapshotSha256: "a".repeat(64), result: "supported", evidenceDelta: [],
  limitations: [`Evidence for ${id}`], verifiedAtMs: 1,
});
const detail = () => within(screen.getByRole("region", { name: "Independent verification" }));

beforeEach(() => {
  useVerificationWrites.setState({ pending: new Set(), receipts: new Map() });
  vi.spyOn(api, "listVerificationClaims").mockResolvedValue([claim("A"), claim("B")]);
  vi.spyOn(api, "listVerifications").mockResolvedValue([]);
});

test("switching claims hides previous history immediately while new history loads", async () => {
  const pending = deferred<VerificationRecord[]>();
  vi.mocked(api.listVerifications).mockImplementation(id => id === "A"
    ? Promise.resolve([record("A")]) : pending.promise);
  render(<VerificationPage />);
  await screen.findByText("Evidence for A");
  await userEvent.click(screen.getByRole("button", { name: "Claim BB" }));
  expect(screen.queryByText("Evidence for A")).not.toBeInTheDocument();
  await act(async () => pending.resolve([record("B")]));
  expect(screen.getByText("Evidence for B")).toBeInTheDocument();
});

test("a save completed after selecting another claim cannot contaminate its history", async () => {
  const pending = deferred<VerificationRecord>();
  vi.spyOn(api, "verifyFinding").mockReturnValue(pending.promise);
  render(<VerificationPage />);
  await screen.findByRole("heading", { name: "Claim A" });
  await userEvent.click(screen.getByRole("button", { name: "Record verification" }));
  await userEvent.click(screen.getByRole("button", { name: "Claim BB" }));
  await act(async () => pending.resolve(record("A")));
  expect(detail().queryByText("Evidence for A")).not.toBeInTheDocument();
  expect(detail().getByRole("heading", { name: "Claim B" })).toBeInTheDocument();
});

test("a late history read does not erase a newly saved immutable record", async () => {
  const pending = deferred<VerificationRecord[]>();
  vi.mocked(api.listVerifications).mockReturnValue(pending.promise);
  vi.spyOn(api, "verifyFinding").mockResolvedValue(record("A", "new"));
  render(<VerificationPage />);
  await screen.findByRole("heading", { name: "Claim A" });
  await userEvent.click(screen.getByRole("button", { name: "Record verification" }));
  await screen.findByText("Evidence for new");
  await act(async () => pending.resolve([record("A", "old")]));
  expect(screen.getByText("Evidence for new")).toBeInTheDocument();
  expect(screen.getByText("Evidence for old")).toBeInTheDocument();
});

test("returning to a claim during its save keeps it busy and receives the saved record", async () => {
  const pending = deferred<VerificationRecord>();
  vi.spyOn(api, "verifyFinding").mockReturnValue(pending.promise);
  render(<VerificationPage />);
  await screen.findByRole("heading", { name: "Claim A" });
  await userEvent.click(screen.getByRole("button", { name: "Record verification" }));
  await userEvent.click(screen.getByRole("button", { name: "Claim BB" }));
  await userEvent.click(screen.getByRole("button", { name: "Claim AA" }));
  expect(screen.getByRole("button", { name: "Saving…" })).toBeDisabled();
  await act(async () => pending.resolve(record("A", "returned")));
  expect(await screen.findByText("Evidence for returned")).toBeInTheDocument();
});

test("batched save completions retain receipts for each claim", async () => {
  const first = deferred<VerificationRecord>();
  const second = deferred<VerificationRecord>();
  vi.spyOn(api, "verifyFinding").mockImplementation(id => id === "A" ? first.promise : second.promise);
  render(<VerificationPage />);
  await screen.findByRole("heading", { name: "Claim A" });
  await userEvent.click(screen.getByRole("button", { name: "Record verification" }));
  await userEvent.click(screen.getByRole("button", { name: "Claim BB" }));
  await userEvent.click(screen.getByRole("button", { name: "Record verification" }));
  await userEvent.click(screen.getByRole("button", { name: "Claim AA" }));
  await act(async () => {
    first.resolve(record("A", "first-batch"));
    second.resolve(record("B", "second-batch"));
  });
  expect(screen.getByText("Evidence for first-batch")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Claim BB" }));
  expect(screen.getByText("Evidence for second-batch")).toBeInTheDocument();
});

test("a receipt is released once authoritative history contains it", async () => {
  const saved = record("A", "acknowledged");
  vi.mocked(api.listVerifications).mockResolvedValue([saved]);
  vi.spyOn(api, "verifyFinding").mockResolvedValue(saved);
  render(<VerificationPage />);
  await screen.findByText("Evidence for acknowledged");
  await userEvent.click(screen.getByRole("button", { name: "Record verification" }));
  await waitFor(() => expect(useVerificationWrites.getState().receipts.size).toBe(0));
  expect(screen.getByText("Evidence for acknowledged")).toBeInTheDocument();
});

test("filtering out a selected claim removes its editable verdict and history", async () => {
  render(<VerificationPage />);
  await screen.findByRole("heading", { name: "Claim A" });
  fireEvent.change(screen.getByLabelText("Search claims"), { target: { value: "Claim B" } });
  expect(screen.queryByRole("heading", { name: "Claim A" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Record verification" })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Claim BB" }));
  expect(detail().getByRole("heading", { name: "Claim B" })).toBeInTheDocument();
});

test("returning to the list clears the claim rather than silently editing the first claim", async () => {
  render(<VerificationPage />);
  await screen.findByRole("heading", { name: "Claim A" });
  await userEvent.click(screen.getByRole("button", { name: "Back to findings" }));
  expect(screen.queryByRole("button", { name: "Record verification" })).not.toBeInTheDocument();
});

test("claim changes clear a draft verdict, limitations, and previous history errors", async () => {
  vi.mocked(api.listVerifications).mockRejectedValueOnce("A history unavailable").mockResolvedValue([]);
  render(<VerificationPage />);
  await screen.findByText("A history unavailable");
  await userEvent.type(screen.getByLabelText("Limitations"), "Only checked A");
  await userEvent.selectOptions(screen.getByLabelText("Verdict"), "refuted");
  await userEvent.click(screen.getByRole("button", { name: "Claim BB" }));
  expect(screen.getByLabelText("Limitations")).toHaveValue("");
  expect(screen.getByLabelText("Verdict")).toHaveValue("inconclusive");
  expect(screen.queryByText("A history unavailable")).not.toBeInTheDocument();
});

test("an initial claim load failure offers recovery", async () => {
  vi.mocked(api.listVerificationClaims).mockRejectedValueOnce("Database temporarily unavailable");
  render(<VerificationPage />);
  await screen.findByText("Database temporarily unavailable");
  await userEvent.click(screen.getByRole("button", { name: "Retry claims" }));
  await waitFor(() => expect(screen.getByRole("heading", { name: "Claim A" })).toBeInTheDocument());
  expect(screen.queryByText("Database temporarily unavailable")).not.toBeInTheDocument();
});

test("large verification queues render bounded pages while keeping every claim reachable", async () => {
  vi.mocked(api.listVerificationClaims).mockResolvedValue(Array.from({ length: 125 }, (_, index) => claim(String(index))));
  render(<VerificationPage />);
  await screen.findByRole("heading", { name: "Claim 0" });
  expect(screen.getAllByRole("button", { name: /^Claim / })).toHaveLength(50);
  await userEvent.click(screen.getByRole("button", { name: "Last page of verification claims" }));
  expect(screen.getAllByRole("button", { name: /^Claim / })).toHaveLength(25);
  await userEvent.click(screen.getByRole("button", { name: "Claim 124124" }));
  expect(detail().getByRole("heading", { name: "Claim 124" })).toBeInTheDocument();
});
