import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../lib/api";
import { save } from "../lib/dialog";
import { useToastStore } from "../lib/stores";
import type { ComplianceAssessment, ComplianceReportPreview, ComplianceReportReceipt } from "../lib/types";
import { ReportStudioPage } from "./ReportStudio";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("../lib/dialog", () => ({ save: vi.fn() }));
const transport = vi.hoisted(() => ({ serverMode: false }));
vi.mock("../lib/transport", () => ({ get serverMode() { return transport.serverMode; }, httpInvoke: vi.fn() }));

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
    targetLabel: `/project/${id}`, createdAtMs: 1, collectionLimits: [], controls: [],
    summary: { total: 0, supported: 0, partial: 0, gap: 0, manualReview: 0,
      notApplicable: 0, evidenceCoveragePercent: 0 },
  };
}
const preview: ComplianceReportPreview = {
  format: "pdf", mediaType: "application/pdf", suggestedFileName: "assessment-a.pdf",
  content: "Compiled assessment A", truncated: false, bytes: 100, warnings: [],
};

beforeEach(() => {
  transport.serverMode = false;
  vi.mocked(save).mockReset();
  useToastStore.setState({ toasts: [] });
  vi.spyOn(api, "listComplianceAssessments").mockResolvedValue([assessment("A"), assessment("B")]);
  vi.spyOn(api, "previewComplianceReport").mockResolvedValue(preview);
  vi.spyOn(api, "writeComplianceReport").mockImplementation(async (request, outputPath) => ({
    id: "receipt", ...request, outputPath,
    contentSha256: "abcdef0123456789", createdAtMs: 1,
  }));
});

test("browser reports require a server destination and save without a native dialog", async () => {
  transport.serverMode = true;
  render(<ReportStudioPage />);
  const button = await screen.findByRole("button", { name: "Save to server" });
  expect(button).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Report file on server"), { target: { value: "   " } });
  expect(button).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Report file on server"), { target: { value: " /reports/current.pdf " } });
  await userEvent.click(button);
  await waitFor(() => expect(api.writeComplianceReport).toHaveBeenCalledWith(
    expect.objectContaining({ assessmentId: "A", format: "pdf" }), "/reports/current.pdf",
  ));
  expect(save).not.toHaveBeenCalled();
  expect(screen.getByRole("status")).toHaveTextContent("/reports/current.pdf");
});

test("editing the server destination while compilation is pending cancels the obsolete save", async () => {
  transport.serverMode = true;
  const pending = deferred<ComplianceReportPreview>();
  vi.mocked(api.previewComplianceReport).mockReturnValueOnce(pending.promise);
  render(<ReportStudioPage />);
  fireEvent.change(await screen.findByLabelText("Report file on server"), { target: { value: "/reports/old.pdf" } });
  await userEvent.click(screen.getByRole("button", { name: "Save to server" }));
  fireEvent.change(screen.getByLabelText("Report file on server"), { target: { value: "/reports/new.pdf" } });
  await act(async () => pending.resolve(preview));
  expect(api.writeComplianceReport).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Save to server" }));
  await waitFor(() => expect(api.writeComplianceReport).toHaveBeenCalledWith(expect.anything(), "/reports/new.pdf"));
});

test("server write failures are visible and a retry announces the saved path", async () => {
  transport.serverMode = true;
  vi.mocked(api.writeComplianceReport).mockRejectedValueOnce("Destination directory does not exist");
  render(<ReportStudioPage />);
  fireEvent.change(await screen.findByLabelText("Report file on server"), { target: { value: "/reports/current.pdf" } });
  await userEvent.click(screen.getByRole("button", { name: "Save to server" }));
  expect(await screen.findByText("Destination directory does not exist")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Save to server" }));
  await waitFor(() => expect(api.writeComplianceReport).toHaveBeenCalledTimes(2));
  expect(screen.queryByText("Destination directory does not exist")).not.toBeInTheDocument();
  expect(screen.getByRole("status")).toHaveTextContent("/reports/current.pdf");
});

test.each(["assessment", "metadata", "A to B to A"])(
  "a submitted save does not mark changed %s inputs as saved", async (change) => {
    const pending = deferred<ComplianceReportReceipt>();
    vi.mocked(save).mockResolvedValue("/reports/a.pdf");
    vi.mocked(api.writeComplianceReport).mockReturnValueOnce(pending.promise);
    render(<ReportStudioPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Save…" }));
    await waitFor(() => expect(api.writeComplianceReport).toHaveBeenCalledTimes(1));
    const [request] = vi.mocked(api.writeComplianceReport).mock.calls[0];
    if (change === "metadata") {
      fireEvent.change(screen.getByLabelText("Report title"), { target: { value: "Unsaved title" } });
    } else {
      await userEvent.selectOptions(screen.getByLabelText("Durable assessment"), "B");
      if (change === "A to B to A") await userEvent.selectOptions(screen.getByLabelText("Durable assessment"), "A");
    }
    await act(async () => pending.resolve({
      id: "receipt-a", ...request, outputPath: "/reports/a.pdf",
      contentSha256: "abcdef0123456789", createdAtMs: 1,
    }));
    expect(screen.queryByText("Saved report to /reports/a.pdf")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save…" })).toBeEnabled();
    expect(useToastStore.getState().toasts).toContainEqual(expect.objectContaining({
      kind: "success", message: expect.stringContaining("/reports/a.pdf"),
    }));
  },
);

test.each(["assessment", "format", "metadata", "disclosure", "A to B to A"])(
  "a pending preview cannot publish after changing %s", async (change) => {
    const pending = deferred<ComplianceReportPreview>();
    vi.mocked(api.previewComplianceReport).mockReturnValueOnce(pending.promise);
    render(<ReportStudioPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Build preview" }));
    if (change === "assessment" || change === "A to B to A") {
      await userEvent.selectOptions(screen.getByLabelText("Durable assessment"), "B");
      if (change === "A to B to A") await userEvent.selectOptions(screen.getByLabelText("Durable assessment"), "A");
    } else if (change === "format") {
      await userEvent.click(screen.getByRole("button", { name: /Self-contained HTML/ }));
    } else if (change === "disclosure") {
      await userEvent.click(screen.getByRole("switch", { name: "Include evidence references" }));
    } else {
      fireEvent.change(screen.getByLabelText("Report title"), { target: { value: "Edited report" } });
    }
    await act(async () => pending.resolve(preview));
    expect(screen.queryByText("Compiled assessment A")).not.toBeInTheDocument();
    expect(screen.getByText("Preview has not been compiled")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Build preview" })).toBeEnabled();
  },
);

test("an obsolete preview failure does not become the current report's error", async () => {
  const pending = deferred<ComplianceReportPreview>();
  vi.mocked(api.previewComplianceReport).mockReturnValueOnce(pending.promise);
  render(<ReportStudioPage />);
  await userEvent.click(await screen.findByRole("button", { name: "Build preview" }));
  await userEvent.selectOptions(screen.getByLabelText("Durable assessment"), "B");
  await act(async () => pending.reject("Assessment A unavailable"));
  expect(screen.queryByText("Assessment A unavailable")).not.toBeInTheDocument();
});

test.each([
  { name: "rejected", fail: () => Promise.reject("File dialog unavailable") },
  { name: "synchronously refused", fail: () => { throw "File dialog unavailable"; } },
])("a $name save dialog shows an error and allows retry", async ({ fail }) => {
  vi.mocked(save).mockImplementationOnce(fail).mockResolvedValueOnce("/reports/a.pdf");
  render(<ReportStudioPage />);
  await userEvent.click(await screen.findByRole("button", { name: "Save…" }));
  expect(await screen.findByText("File dialog unavailable")).toBeInTheDocument();
  expect(api.writeComplianceReport).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Save…" }));
  await waitFor(() => expect(api.writeComplianceReport).toHaveBeenCalledTimes(1));
  expect(screen.queryByText("File dialog unavailable")).not.toBeInTheDocument();
});

test("save stays busy throughout the dialog and refuses an obsolete destination", async () => {
  const destination = deferred<string | null>();
  vi.mocked(save).mockReturnValue(destination.promise);
  render(<ReportStudioPage />);
  await userEvent.click(await screen.findByRole("button", { name: "Save…" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  expect(screen.getByRole("button", { name: "Save…" })).toBeDisabled();
  await userEvent.selectOptions(screen.getByLabelText("Durable assessment"), "B");
  await act(async () => destination.resolve("/reports/a.pdf"));
  expect(api.writeComplianceReport).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Save…" })).toBeEnabled();
});

test.each(["changed", "unmounted"])("save stops before opening a dialog when its pending preview is %s", async (change) => {
  const pending = deferred<ComplianceReportPreview>();
  vi.mocked(api.previewComplianceReport).mockReturnValueOnce(pending.promise);
  const view = render(<ReportStudioPage />);
  await userEvent.click(await screen.findByRole("button", { name: "Save…" }));
  if (change === "unmounted") view.unmount();
  else fireEvent.change(screen.getByLabelText("Organization"), { target: { value: "New organization" } });
  await act(async () => pending.resolve(preview));
  expect(save).not.toHaveBeenCalled();
  expect(api.writeComplianceReport).not.toHaveBeenCalled();
});

test("a current preview renders and save writes the selected assessment and edited metadata", async () => {
  vi.mocked(save).mockResolvedValue("/reports/current.html");
  vi.mocked(api.previewComplianceReport).mockResolvedValue({ ...preview, format: "html",
    mediaType: "text/html", suggestedFileName: "current.html", content: "Current edited report" });
  render(<ReportStudioPage />);
  await userEvent.selectOptions(await screen.findByLabelText("Durable assessment"), "B");
  await userEvent.click(screen.getByRole("button", { name: /Self-contained HTML/ }));
  fireEvent.change(screen.getByLabelText("Report title"), { target: { value: "Current title" } });
  await userEvent.click(screen.getByRole("switch", { name: "Include evidence references" }));
  await userEvent.click(screen.getByRole("button", { name: "Build preview" }));
  expect(await screen.findByText("Current edited report")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Save…" }));
  await waitFor(() => expect(api.writeComplianceReport).toHaveBeenCalledWith({
    assessmentId: "B", format: "html", metadata: {
      title: "Current title", organization: "Example", assessor: "Reviewer B", classification: "Confidential",
      executiveSummary: "This report summarizes collected evidence, automated readiness signals, open gaps, and qualified reviewer decisions. It does not assert certification or legal conformity.",
      includeEvidence: false, includeReviews: true, includeReferences: true,
    },
  }, "/reports/current.html"));
  expect(api.previewComplianceReport).toHaveBeenCalledTimes(1);
  expect(save).toHaveBeenCalledWith({ defaultPath: "current.html", filters: [{ name: "Self-contained HTML", extensions: ["html"] }] });
  expect(useToastStore.getState().toasts).toContainEqual(expect.objectContaining({ kind: "success" }));
});

test("cancelling a save dialog releases the controls without writing a report", async () => {
  vi.mocked(save).mockResolvedValue(null);
  render(<ReportStudioPage />);
  await userEvent.click(await screen.findByRole("button", { name: "Save…" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  expect(api.writeComplianceReport).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Save…" })).toBeEnabled();
  expect(useToastStore.getState().toasts).toEqual([]);
});
