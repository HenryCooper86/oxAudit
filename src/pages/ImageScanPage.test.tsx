import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { ImageScanPage } from "./ImageScanPage";

const listen = vi.fn().mockResolvedValue(() => {});
vi.mock("@tauri-apps/api/event", () => ({
  listen: (...args: unknown[]) => listen(...args),
}));

const scanImage = vi.fn();
const cancelImageScan = vi.fn();
vi.mock("../lib/api", () => ({
  api: {
    scanImage: (...args: unknown[]) => scanImage(...args),
    cancelImageScan: (...args: unknown[]) => cancelImageScan(...args),
  },
}));

const toast = vi.fn();
vi.mock("../lib/stores", () => ({
  useToastStore: (selector: (state: { push: typeof toast }) => unknown) =>
    selector({ push: toast }),
}));

const outcome = {
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
  expect(cancelImageScan).toHaveBeenCalled();
  expect(scanImage).toHaveBeenCalledWith({ target: "saved.tar", advisoryDbPath: null, offline: true });
  release(outcome);
});

test("pressing Enter while an image scan is running cannot start a second scan", async () => {
  scanImage.mockClear();
  scanImage.mockReturnValue(new Promise(() => {}));
  render(<ImageScanPage />);
  await userEvent.type(screen.getByLabelText("Image target"), "saved.tar{enter}{enter}");
  expect(scanImage).toHaveBeenCalledTimes(1);
});

test("a late image event subscription is released after the page unmounts", async () => {
  let resolve!: (stop: () => void) => void;
  listen.mockReturnValue(new Promise((done) => { resolve = done; }));
  const stop = vi.fn();
  const view = render(<ImageScanPage />);
  view.unmount();
  await act(async () => resolve(stop));
  expect(stop).toHaveBeenCalledOnce();
});
