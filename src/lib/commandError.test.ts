import { expect, test } from "vitest";
import { errorMessage, normalizeCommandError } from "./commandError";

test("errorMessage reads structured CommandErrors instead of [object Object]", () => {
  expect(errorMessage({ code: "notFound", message: "Run not found", detail: null, retryable: false })).toBe("Run not found");
  expect(errorMessage({ message: "plain object" })).toBe("plain object");
  expect(errorMessage(new Error("boom"))).toBe("boom");
  expect(errorMessage("text")).toBe("text");
  expect(errorMessage({})).toBe("The operation could not be completed.");
  expect(errorMessage(null, "Custom fallback")).toBe("Custom fallback");
});

test("normalizeCommandError keeps its scan fallback by default", () => {
  expect(normalizeCommandError({}).message).toBe("The scan could not be completed.");
});
