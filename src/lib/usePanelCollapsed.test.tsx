import { act, renderHook } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { usePanelCollapsed } from "./usePanelCollapsed";

it("keeps panel toggles usable when browser storage access is blocked", () => {
  vi.spyOn(window, "localStorage", "get").mockImplementation(() => {
    throw new DOMException("Storage blocked", "SecurityError");
  });
  const { result } = renderHook(() => usePanelCollapsed("findings"));
  expect(result.current[0]).toBe(false);
  act(() => result.current[1]());
  expect(result.current[0]).toBe(true);
  act(() => result.current[1]());
  expect(result.current[0]).toBe(false);
});
