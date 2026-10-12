import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../lib/api";
import { useAppStore, useToastStore } from "../lib/stores";
import type { ComplianceAssessment, ComplianceAssessmentView, ComplianceReview } from "../lib/types";
import { ComplianceCenterPage } from "./ComplianceCenter";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (cause: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function assessment(id: string): ComplianceAssessment {
  return {
    schemaVersion: 1, id, profileId: "profile", profileName: `Assessment ${id}`,
    profileVersion: "1", domain: "Development", sourceLabel: "Source",
    sourceUrl: "https://example.com/controls", disclaimer: "Evidence readiness",
    metadata: { title: id, organization: "Example", assessor: `Reviewer ${id}`, scope: "Project" },
    targetLabel: `/project/${id}`, createdAtMs: 1, collectionLimits: [],
    controls: [{ controlId: "shared-control", reference: "C-1", title: "Project evidence",
      objective: "Review project evidence", assurance: "humanAttestation",
      automatedStatus: "manualReview", rationale: "Requires review", evidence: [] }],
    summary: { total: 1, supported: 0, partial: 0, gap: 0, manualReview: 1,
      notApplicable: 0, evidenceCoveragePercent: 0 },
  };
}
const first = assessment("A"), second = assessment("B");
const view = (value: ComplianceAssessment): ComplianceAssessmentView => ({ assessment: value, reviews: [] });

beforeEach(() => {
  useAppStore.setState({ activeProject: null });
  useToastStore.setState({ toasts: [] });
  vi.spyOn(api, "listComplianceProfiles").mockResolvedValue([]);
  vi.spyOn(api, "listComplianceAssessments").mockResolvedValue([first, second]);
});

test.each(["success", "failure"])("a delayed assessment %s cannot replace a newer selection", async (outcome) => {
  const old = deferred<ComplianceAssessmentView>();
  vi.spyOn(api, "loadComplianceAssessment").mockImplementation(async (id) =>
    id === "A" ? old.promise : view(second),
  );
  render(<ComplianceCenterPage />);
  await userEvent.click(await screen.findByRole("button", { name: /Assessment A/ }));
  await userEvent.click(screen.getByRole("button", { name: /Assessment B/ }));
  expect(await screen.findByRole("heading", { name: "Assessment B · 1" })).toBeInTheDocument();

  await act(async () => {
    if (outcome === "success") old.resolve(view(first));
    else old.reject("Old assessment unavailable");
  });
  expect(screen.getByRole("heading", { name: "Assessment B · 1" })).toBeInTheDocument();
  expect(screen.queryByText("Old assessment unavailable")).not.toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Assessment A · 1" })).not.toBeInTheDocument();
});

test("an old assessment response cannot finish the latest selection's loading state", async () => {
  const old = deferred<ComplianceAssessmentView>(), latest = deferred<ComplianceAssessmentView>();
  vi.spyOn(api, "loadComplianceAssessment").mockImplementation((id) => id === "A" ? old.promise : latest.promise);
  render(<ComplianceCenterPage />);
  await userEvent.click(await screen.findByRole("button", { name: /Assessment A/ }));
  await userEvent.click(screen.getByRole("button", { name: /Assessment B/ }));
  await act(async () => old.resolve(view(first)));
  expect(screen.getByText("Loading assessment evidence")).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Assessment A · 1" })).not.toBeInTheDocument();
  await act(async () => latest.resolve(view(second)));
  expect(screen.getByRole("heading", { name: "Assessment B · 1" })).toBeInTheDocument();
});

test("a delayed review remains attached to the assessment it was recorded for", async () => {
  const saved = deferred<ComplianceReview>();
  vi.spyOn(api, "loadComplianceAssessment").mockImplementation(async (id) => view(id === "A" ? first : second));
  vi.spyOn(api, "saveComplianceReview").mockReturnValue(saved.promise);
  render(<ComplianceCenterPage />);
  await userEvent.click(await screen.findByRole("button", { name: /Assessment A/ }));
  await screen.findByRole("heading", { name: "Assessment A · 1" });
  await userEvent.click(screen.getByText("C-1 · Project evidence"));
  fireEvent.change(screen.getByLabelText("Decision note"), { target: { value: "Review of project A" } });
  await userEvent.click(screen.getByRole("button", { name: "Record review" }));
  await waitFor(() => expect(api.saveComplianceReview).toHaveBeenCalledWith(
    "A", "shared-control", "manualReview", "Review of project A", "Reviewer A",
  ));
  await userEvent.click(screen.getByRole("button", { name: /Assessment B/ }));
  await screen.findByRole("heading", { name: "Assessment B · 1" });
  await act(async () => saved.resolve({ id: "review-a", assessmentId: "A", controlId: "shared-control",
    status: "supported", note: "Review of project A", author: "Reviewer A", reviewedAtMs: 2 }));

  expect(screen.queryByText(/Latest review by/)).not.toBeInTheDocument();
  expect(screen.queryByText("Review: Supported by review")).not.toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Assessment B · 1" })).toBeInTheDocument();
});

test("a review saved for the selected assessment refreshes its visible decision", async () => {
  vi.spyOn(api, "loadComplianceAssessment").mockResolvedValue(view(second));
  vi.spyOn(api, "saveComplianceReview").mockResolvedValue({ id: "review-b", assessmentId: "B",
    controlId: "shared-control", status: "supported", note: "Evidence reviewed for B",
    author: "Reviewer B", reviewedAtMs: 2 });
  render(<ComplianceCenterPage />);
  await userEvent.click(await screen.findByRole("button", { name: /Assessment B/ }));
  await screen.findByRole("heading", { name: "Assessment B · 1" });
  await userEvent.click(screen.getByText("C-1 · Project evidence"));
  await userEvent.selectOptions(screen.getByLabelText("Decision"), "supported");
  fireEvent.change(screen.getByLabelText("Decision note"), { target: { value: "Evidence reviewed for B" } });
  await userEvent.click(screen.getByRole("button", { name: "Record review" }));
  expect(await screen.findByText("Review: Supported by review")).toBeInTheDocument();
  expect(screen.getByText(/Latest review by/)).toHaveTextContent("Reviewer B");
  expect(screen.getByText(/Latest review by/)).toHaveTextContent("Evidence reviewed for B");
});
