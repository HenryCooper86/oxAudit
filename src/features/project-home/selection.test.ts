import { expect, test, vi } from "vitest";
test("selected project survives a store reload without restoring assistant runtime authority", async () => {
  localStorage.clear();
  vi.resetModules();
  const first = (await import("../../lib/stores")).useAppStore;
  first.getState().setSelectedProject("/remembered");
  first.getState().setActiveProject("/runtime");
  vi.resetModules();
  const restored = (await import("../../lib/stores")).useAppStore;
  expect(restored.getState().selectedProject).toBe("/remembered");
  expect(restored.getState().activeProject).toBeNull();
  localStorage.setItem("vc.selectedProject", '{"version":1,"path":17}');
  vi.resetModules();
  const malformed = (await import("../../lib/stores")).useAppStore;
  expect(malformed.getState().selectedProject).toBeNull();
  localStorage.clear();
});
