import { canonicalMetadata, canonicalPage } from "../../tests/fixtures/pagedResults";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { ImageScanPage } from "./ImageScanPage";
import { useScanWorkStore } from "../features/project-home/coordinator";

const listen = vi.fn().mockResolvedValue(() => {});
vi.mock("@tauri-apps/api/event", () => ({
  listen: (...args: unknown[]) => listen(...args),
}));

const scanImage = vi.fn();
const cancelImageScan = vi.fn();
const cancelScanWork = vi.fn();
const listCanonicalRuns = vi.fn();
const loadCanonicalProjection = vi.fn();
const loadCanonicalProjectionMetadata = vi.fn();
const loadCanonicalProjectionPage = vi.fn();
vi.mock("../lib/api", () => ({
  api: {
    scanImage: (...args: unknown[]) => scanImage(...args),
    cancelImageScan: (...args: unknown[]) => cancelImageScan(...args),
    cancelScanWork: (...args: unknown[]) => cancelScanWork(...args),
    scanWorkStatus: async () => ({ active: null, recent: [] }),
    listCanonicalRuns: (...args: unknown[]) => listCanonicalRuns(...args),
    loadCanonicalProjection: (...args: unknown[]) => loadCanonicalProjection(...args),
    loadCanonicalProjectionMetadata: (...args: unknown[]) => loadCanonicalProjectionMetadata(...args),
    loadCanonicalProjectionPage: (...args: unknown[]) => loadCanonicalProjectionPage(...args),
  },
}));

const toast = vi.fn();
vi.mock("../lib/stores", async importOriginal => ({
  ...await importOriginal<typeof import("../lib/stores")>(),
  useToastStore: (selector: (state: { push: typeof toast }) => unknown) =>
    selector({ push: toast }),
}));

const outcome = {
  runId: "saved-image",
  imageDigest: "sha256:immutable-image",
  layers: [{ name: "layer", digest: "sha256:immutable-layer", sizeBytes: 42, mediaType: "application/vnd.oci.image.layer.v1.tar" }],
  offline: false,
  result: {
    target: "registry.local/app:1.0",
    summary: { components: 1, vulnerabilities: 1, critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
    components: [
      {
        product: "libc6",
        version: "2.36-9+deb12u3",
        vendor: "",
        paths: ["registry.local/app:1.0@abc!/var/lib/dpkg/status"],
        vulnerabilities: [
          {
            cveId: "CVE-2099-2222",
            severity: "critical",
            score: 9.8,
            cvssVersion: null,
            cvssVector: null,
            source: "OSV",
            remarks: null,
            epssProbability: null,
            epssPercentile: null,
            knownExploited: false,
            ransomware: false,
            publicExploit: false,
            fixedIn: "2.40.0-1",
          },
        ],
        detectedBy: ["oxaudit"],
      },
    ],
    databaseLastUpdated: null,
    durationMs: 10,
    scanners: ["oxaudit"],
    semanticAnalysis: null,
  },
  notes: ["offline scan: 1 CPE-keyed component(s) can only be answered by NVD"],
};

beforeEach(() => {
  vi.clearAllMocks();
  loadCanonicalProjectionMetadata.mockImplementation(async id => canonicalMetadata(await loadCanonicalProjection.getMockImplementation()?.(id)));
  loadCanonicalProjectionPage.mockImplementation(async (id, section, query) => canonicalPage(await loadCanonicalProjection.getMockImplementation()?.(id), section, query));
  useScanWorkStore.setState({ active: null, check: null, backend: { active: null, recent: [] }, lastTargets: {}, recoveryError: null });
  listCanonicalRuns.mockResolvedValue([]);
  cancelScanWork.mockResolvedValue(true);
  listen.mockResolvedValue(() => {});
});

test("a registry scan renders components, vulnerabilities, and honest notes", async () => {
  scanImage.mockResolvedValue(outcome);
  render(<ImageScanPage />);
  const target = screen.getByLabelText("Image target");
  await userEvent.type(target, "registry.local/app:1.0");
  await userEvent.click(screen.getByRole("button", { name: /^scan$/i }));
  expect(scanImage).toHaveBeenCalledWith({
    target: "registry.local/app:1.0",
    advisoryDbPath: null,
    offline: false,
    operationId: expect.any(String),
  });
  expect(await screen.findByText("libc6")).toBeInTheDocument();
  expect(screen.getByText(/CVE-2099-2222/)).toBeInTheDocument();
  expect(screen.getByText(/1 critical/)).toBeInTheDocument();
  expect(screen.getByText(/CPE-keyed component/)).toBeInTheDocument();
});

test("the offline switch travels with the request and cancel is reachable while running", async () => {
  let release!: (value: typeof outcome) => void;
  scanImage.mockImplementation(
    () => new Promise((resolve) => {
      release = resolve;
    }),
  );
  render(<ImageScanPage />);
  await userEvent.type(screen.getByLabelText("Image target"), "saved.tar");
  await userEvent.click(screen.getByRole("switch", { name: /offline advisories/i }));
  await userEvent.click(screen.getByRole("button", { name: /^scan$/i }));
  await userEvent.click(screen.getByRole("button", { name: /cancel/i }));
  expect(cancelScanWork).toHaveBeenCalledWith(scanImage.mock.calls[0][0].operationId);
  expect(cancelImageScan).not.toHaveBeenCalled();
  expect(scanImage).toHaveBeenCalledWith({ target: "saved.tar", advisoryDbPath: null, offline: true, operationId: expect.any(String) });
  await act(async () => release(outcome));
  expect(toast).not.toHaveBeenCalledWith("success", expect.any(String));
});

test("editing, choosing, or pressing Enter on an image target requires the explicit Scan action", async () => {
  scanImage.mockClear();
  scanImage.mockReturnValue(new Promise(() => {}));
  render(<ImageScanPage />);
  await userEvent.type(screen.getByLabelText("Image target"), "saved.tar{enter}{enter}");
  expect(scanImage).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Choose image file…" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Choose OCI folder…" })).toBeEnabled();
  await userEvent.click(screen.getByRole("button", { name: /^scan$/i }));
  expect(scanImage).toHaveBeenCalledTimes(1);
});

test("late image event subscriptions are each released after the page unmounts", async () => {
  const pending: Array<(stop: () => void) => void> = [];
  listen.mockImplementation(() => new Promise(done => { pending.push(done); }));
  const view = render(<ImageScanPage />);
  view.unmount();
  const stops = pending.map(() => vi.fn());
  await act(async () => pending.forEach((resolve, index) => resolve(stops[index])));
  expect(stops).toHaveLength(2);
  for (const stop of stops) expect(stop).toHaveBeenCalledOnce();
});

test("a saved image receipt reloads its immutable digest and layer identities", async () => {
  listCanonicalRuns.mockResolvedValue([{ id: "saved-image", kind: "image", targetLabel: "registry.local/app:1.0", state: "completed", updatedAtMs: 2, createdAtMs: 1, attempt: 1, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] }]);
  loadCanonicalProjection.mockResolvedValue(outcome);
  render(<ImageScanPage />);
  expect(await screen.findByText("sha256:immutable-image")).toBeInTheDocument();
  expect(await screen.findByText("sha256:immutable-layer")).toBeInTheDocument();
  expect(screen.getByLabelText("Image target")).toHaveValue("registry.local/app:1.0");
  expect(loadCanonicalProjection).not.toHaveBeenCalled();
  expect(loadCanonicalProjectionMetadata).toHaveBeenCalledWith("saved-image");
  expect(scanImage).not.toHaveBeenCalled();
  expect(screen.queryByText(/not persisted as canonical runs/)).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Open Export Center' }));
  const { useAppStore } = await import('../lib/stores');
  expect(useAppStore.getState().exportHandoff).toEqual({ runId: 'saved-image' });
});

test("a recovered image operation blocks another launch and cancels only that operation", async () => {
  const { reconcileBackendWork } = await import("../features/project-home/coordinator");
  reconcileBackendWork({ active: { operationId: "recovered-image", kind: "image", target: "registry.local/busy:1", status: "running", runId: null, startedAtMs: 1, updatedAtMs: 2 }, recent: [] });
  render(<ImageScanPage />);
  expect(screen.getByRole("button", { name: /^scan$/i })).toBeDisabled();
  await userEvent.click(screen.getByRole("button", { name: /^cancel$/i }));
  expect(cancelScanWork).toHaveBeenCalledWith("recovered-image");
  await waitFor(() => expect(scanImage).not.toHaveBeenCalled());
});

test('a failed saved image receipt cannot report successful zero-vulnerability coverage', async () => {
  listCanonicalRuns.mockResolvedValue([{ id: 'failed-image', kind: 'image', targetLabel: 'registry.local/app:1.0', state: 'failed', attempt: 1, createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: ['Registry request failed'] }]);
  loadCanonicalProjection.mockResolvedValue({ ...outcome, runId: 'failed-image', result: { ...outcome.result, components: [], summary: { ...outcome.result.summary, components: 0, vulnerabilities: 0 } }, notes: ['Registry request failed'] });
  const { useAppStore } = await import('../lib/stores');
  render(<ImageScanPage />);
  expect(await screen.findByText(/Latest saved attempt: failed/)).toBeInTheDocument();
  expect(useAppStore.getState().pageStatus['image-scan']?.tone).not.toBe('success');
  expect(useAppStore.getState().pageStatus['image-scan']?.label).toMatch(/failed/);
});

test('saved local image identity is labeled as a pre-scan snapshot and incomplete hashes remain explicit', async () => {
  listCanonicalRuns.mockResolvedValue([{ id: 'saved-image', kind: 'image', targetLabel: 'saved.tar', state: 'incomplete', attempt: 1, createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] }]);
  loadCanonicalProjection.mockResolvedValue({ ...outcome, localEvidence: { kind: 'file', complete: false, hashByteLimit: 64, file: { sizeBytes: 128, sizeSource: 'metadata', bytesHashed: 64, sha256: null, prefixSha256: 'sha256:prefix-only', changedDuringRead: null, complete: false }, notes: ['Hash byte budget reached'] } });
  render(<ImageScanPage />);
  expect(await screen.findByText('sha256:prefix-only')).toBeInTheDocument();
  expect(screen.getByText(/Pre-scan identity snapshot/)).toHaveTextContent(/does not bind the bytes read later by the scan/);
  expect(screen.getByText(/Local identity capture is incomplete/)).toBeInTheDocument();
  expect(screen.getByText(/Prefix SHA-256/)).toHaveTextContent('64 bytes');
});
