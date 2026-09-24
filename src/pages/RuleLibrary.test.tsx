import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { RuleLibraryPage } from "./RuleLibrary";
import type { InstalledRulePack, RuleLibraryPackStatus } from "../lib/types";

const open = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: (...args: unknown[]) => open(...args) }));

const ruleLibraryStatus = vi.fn();
const validateRulePack = vi.fn();
const installRulePack = vi.fn();
const listInstalledRulePacks = vi.fn();
const setRulePackEnabled = vi.fn();
const removeRulePack = vi.fn();
vi.mock("../lib/api", () => ({
  api: {
    ruleLibraryStatus: (...args: unknown[]) => ruleLibraryStatus(...args),
    validateRulePack: (...args: unknown[]) => validateRulePack(...args),
    installRulePack: (...args: unknown[]) => installRulePack(...args),
    listInstalledRulePacks: (...args: unknown[]) => listInstalledRulePacks(...args),
    setRulePackEnabled: (...args: unknown[]) => setRulePackEnabled(...args),
    removeRulePack: (...args: unknown[]) => removeRulePack(...args),
  },
}));

vi.mock("../lib/stores", () => ({
  useToastStore: (selector: (state: { push: () => void }) => unknown) =>
    selector({ push: vi.fn() }),
}));

const builtInPack = (): RuleLibraryPackStatus => ({
  id: "builtin.source",
  name: "Built-in source rules",
  engine: "source_regex",
  version: "1",
  enabled: true,
  license: "Apache-2.0",
  source: "compiled in",
  creationMethod: "independently-derived",
  contentSha256: "a".repeat(64),
  validation: "verified",
  fixtureSummary: "all verified",
  rules: [
    {
      id: "js-eval",
      title: "eval of dynamic input",
      severity: "high",
      scope: ["javascript"],
      provenance: "unit-tested",
      fixtureHealth: "unitTested",
    },
  ],
});

const installedPack = (overrides: Partial<InstalledRulePack> = {}): InstalledRulePack => ({
  id: "rulepack.acme",
  name: "Acme house rules",
  version: "1.2.0",
  tomlSha256: "b".repeat(64),
  contentSha256: "c".repeat(64),
  ruleCount: 7,
  engines: ["source_regex", "secret_regex"],
  enabled: true,
  installedAt: "2026-09-24T00:00:00Z",
  ...overrides,
});

test("installed packs list with their apply state and engine coverage", async () => {
  ruleLibraryStatus.mockResolvedValue([builtInPack()]);
  listInstalledRulePacks.mockResolvedValue([installedPack()]);
  render(<RuleLibraryPage />);
  expect(await screen.findByText("Acme house rules")).toBeInTheDocument();
  expect(screen.getByText(/7 rules · source_regex, secret_regex/)).toBeInTheDocument();
  expect(screen.getByRole("switch", { name: /applies to scans/i })).toBeChecked();
  // The stated limit travels with the list, not buried in docs.
  expect(
    screen.getByText(/only the text engines \(source_regex, secret_regex\) apply today/i),
  ).toBeInTheDocument();
});

test("an empty store says so and points at validation", async () => {
  ruleLibraryStatus.mockResolvedValue([builtInPack()]);
  listInstalledRulePacks.mockResolvedValue([]);
  render(<RuleLibraryPage />);
  expect(await screen.findByText(/no packs installed/i)).toBeInTheDocument();
});

test("a validated pack installs from the file it was validated from", async () => {
  ruleLibraryStatus.mockResolvedValue([builtInPack()]);
  listInstalledRulePacks.mockResolvedValue([]);
  open.mockResolvedValue("/tmp/acme/pack.toml");
  validateRulePack.mockResolvedValue({
    id: "rulepack.acme",
    name: "Acme house rules",
    version: "1.2.0",
    contentSha256: "c".repeat(64),
    ruleCount: 7,
    engines: ["source_regex"],
    fixtureCount: 14,
    license: "Apache-2.0",
    source: "independent fixture",
    validation: "verified",
  });
  installRulePack.mockResolvedValue(installedPack());

  render(<RuleLibraryPage />);
  await userEvent.click(await screen.findByRole("button", { name: /choose pack/i }));
  await screen.findByText("Safe declarative pack verified");
  await userEvent.click(screen.getByRole("button", { name: /install pack/i }));
  await waitFor(() => expect(installRulePack).toHaveBeenCalledWith("/tmp/acme/pack.toml"));
  expect(await screen.findByText(/acme house rules/i)).toBeInTheDocument();
});

test("toggling and removing an installed pack drives the store", async () => {
  ruleLibraryStatus.mockResolvedValue([builtInPack()]);
  listInstalledRulePacks
    .mockResolvedValueOnce([installedPack()])
    .mockResolvedValueOnce([installedPack({ enabled: false })])
    .mockResolvedValue([]);
  render(<RuleLibraryPage />);
  await screen.findByText("Acme house rules");
  await userEvent.click(screen.getByRole("switch", { name: /applies to scans/i }));
  await waitFor(() => expect(setRulePackEnabled).toHaveBeenCalledWith("rulepack.acme", false));
  expect(await screen.findByRole("switch", { name: /disabled/i })).not.toBeChecked();
  await userEvent.click(screen.getByRole("button", { name: /remove/i }));
  await waitFor(() => expect(removeRulePack).toHaveBeenCalledWith("rulepack.acme"));
  expect(await screen.findByText(/no packs installed/i)).toBeInTheDocument();
});
