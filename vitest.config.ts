import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

/**
 * Component tests only.
 *
 * The existing `tests/*.test.ts` suite runs under `node:test` against pure
 * modules and is deliberately left there: it needs no DOM, starts instantly,
 * and `npm test` runs both. Vitest is here for the thing node:test cannot do —
 * render a component and drive it the way a person does.
 *
 * The gap this closes: 20 test files, none of which rendered anything, while
 * `Assistant.tsx` coordinated streaming, tool-call approval, cancellation, and
 * session persistence across 1,500 lines with no interaction-level coverage.
 */
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./tests/setup.ts"],
    // Only the component suite; node:test owns tests/*.test.ts.
    include: ["src/**/*.test.tsx", "src/**/*.test.ts"],
    restoreMocks: true,
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.test.{ts,tsx}", "src/vite-env.d.ts", "src/main.tsx"],
      reporter: ["text-summary"],
      // A ratchet, not a target: set just under the measured totals (81.45 /
      // 76.29 / 77.27 / 84.16 on 2026-10-29) so CI fails when a change lands
      // code without the tests that cover it. Raise these as coverage grows.
      thresholds: {
        statements: 81,
        branches: 76,
        functions: 77,
        lines: 84,
      },
    },
  },
});
