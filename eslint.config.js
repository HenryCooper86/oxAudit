// ESLint flat config. `npm run lint` runs it over the whole repository and CI
// runs the same command in the frontend job.
//
// Scope: the React app (src/), the node:test and Playwright suites (tests/),
// the Node tooling (tools/), the VS Code extension source and the root config
// files. Generated output, vendored corpora and the Rust tree are ignored.
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import jsxA11y from "eslint-plugin-jsx-a11y";
import globals from "globals";

export default tseslint.config(
  {
    ignores: [
      "dist/",
      "dist-ssr/",
      "src-tauri/",
      "playwright-report/",
      "test-results/",
      "coverage/",
      "editors/vscode/out/",
      "editors/vscode/node_modules/",
      // Scanner fixtures: deliberately vulnerable or odd code, not ours to lint.
      "benchmarks/",
      "examples/",
      "tmp/",
      "output/",
      ".claude/",
      ".worktrees/",
      ".superpowers/",
    ],
  },
  {
    linterOptions: {
      // A disable comment that suppresses nothing is a stale claim about the code.
      reportUnusedDisableDirectives: "error",
    },
  },
  js.configs.recommended,
  tseslint.configs.recommended,
  {
    rules: {
      // Leading-underscore names are the codebase's "deliberately unused" marker.
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
          destructuredArrayIgnorePattern: "^_",
          ignoreRestSiblings: true,
        },
      ],
    },
  },
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // A missing dependency is a stale-closure bug, not a style nit: fail CI.
      "react-hooks/exhaustive-deps": "error",
      // The next three are React Compiler readiness rules. This app does not
      // run the compiler, and what they flag here (fetch-on-change effects that
      // set loading/error state, latest-value refs written during render,
      // useCallback inferred deps) is correct under plain React 19.
      "react-hooks/set-state-in-effect": "off",
      "react-hooks/refs": "off",
      "react-hooks/preserve-manual-memoization": "off",
    },
  },
  {
    files: ["src/**/*.tsx"],
    ...jsxA11y.flatConfigs.recommended,
    rules: {
      ...jsxA11y.flatConfigs.recommended.rules,
      // Input, Select and Textarea (src/components/ui) render the native
      // control, so a <label> wrapping one is a real association.
      "jsx-a11y/label-has-associated-control": [
        "error",
        { controlComponents: ["Input", "Select", "Textarea"], depth: 3 },
      ],
    },
  },
  {
    files: ["src/**/*.test.{ts,tsx}", "tests/setup.ts"],
    languageOptions: {
      globals: { ...globals.browser, ...globals.node, ...globals.vitest },
    },
  },
  {
    files: ["src/**/*.test.{ts,tsx}", "tests/**/*.{ts,mjs,js}"],
    rules: {
      // Test doubles and parsed-JSON fixtures reach into deliberately untyped
      // shapes; production code under src/ stays strict.
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
  {
    files: [
      "tests/**/*.{ts,mjs,js}",
      "tools/**/*.{ts,mjs,js}",
      "editors/vscode/src/**/*.ts",
      "*.{js,mjs,cjs,ts}",
    ],
    languageOptions: {
      globals: globals.node,
    },
  },
  {
    files: ["tests/e2e/**/*.mjs"],
    languageOptions: {
      // page.evaluate() callbacks run in the browser.
      globals: { ...globals.node, ...globals.browser },
    },
    rules: {
      // Playwright requires fixtures to destructure their first argument,
      // even when they use no other fixture: `async ({}, use) => …`.
      "no-empty-pattern": ["error", { allowObjectPatternsAsParameters: true }],
    },
  },
);
