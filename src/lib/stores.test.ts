import { expect, test, vi } from "vitest";

test("malformed recent-scan storage cannot break recording a new scan", async () => {
  const scan = { id: "new", kind: "source" as const, path: "/project", at: "2026-10-08T00:00:00Z", findings: 1, critical: 0, high: 1 };
  for (const value of ["null", "{}", '"bad"', "[null]", '[{"id":"incomplete"}]']) {
    vi.resetModules();
    localStorage.setItem("vc.recentScans", value);
    const { useAppStore } = await import("./stores");
    useAppStore.getState().addRecentScan(scan);
    expect(useAppStore.getState().recentScans).toEqual([scan]);
  }
  localStorage.clear();
});

test("valid recent scans survive reloading and duplicate updates", async () => {
  vi.resetModules();
  const scan = { id: "saved", kind: "deps" as const, path: "/project", at: "2026-10-08T00:00:00Z", findings: 3, critical: 0, high: 1 };
  localStorage.setItem("vc.recentScans", JSON.stringify([scan]));
  const { useAppStore } = await import("./stores");
  expect(useAppStore.getState().recentScans).toEqual([scan]);
  useAppStore.getState().addRecentScan({ ...scan, findings: 4 });
  expect(useAppStore.getState().recentScans).toEqual([{ ...scan, findings: 4 }]);
  localStorage.clear();
});
