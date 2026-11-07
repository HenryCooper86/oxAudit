import "vitest";
import type { TestingLibraryMatchers } from "@testing-library/jest-dom/matchers";

// jest-dom 7 augments Vitest's pre-v5 Assertion interface. Vitest 5 exposes
// custom matchers through Matchers, preserving sync and async return types.
declare module "vitest" {
  // Module augmentation must use an interface to merge the upstream matchers.
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface Matchers<R, T> extends TestingLibraryMatchers<R, T> {}
}
