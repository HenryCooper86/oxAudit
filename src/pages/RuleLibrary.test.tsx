import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { RuleLibraryPage } from "./RuleLibrary";
import type { InstalledRulePack, InstalledSignaturePack, RuleLibraryPackStatus, SignaturePackPreview } from "../lib/types";

const open = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: (...args: unknown[]) => open(...args) }));
const transport = vi.hoisted(() => ({ server: false }));
vi.mock("../lib/transport", () => ({ get serverMode() { return transport.server; } }));
beforeEach(() => {
  transport.server = false;
  vi.clearAllMocks();
  listSignaturePacks.mockResolvedValue([]);
  ruleLibraryStatus.mockResolvedValue([]);
  listInstalledRulePacks.mockResolvedValue([]);
});

const ruleLibraryStatus = vi.fn();
const validateRulePack = vi.fn();
const installRulePack = vi.fn();
const listInstalledRulePacks = vi.fn();
const setRulePackEnabled = vi.fn();
const removeRulePack = vi.fn();
const validateSignaturePack = vi.fn();
const installSignaturePack = vi.fn();
const listSignaturePacks = vi.fn();
const setSignaturePackEnabled = vi.fn();
const removeSignaturePack = vi.fn();
vi.mock("../lib/api", () => ({
  api: {
    ruleLibraryStatus: (...args: unknown[]) => ruleLibraryStatus(...args),
    validateRulePack: (...args: unknown[]) => validateRulePack(...args),
    installRulePack: (...args: unknown[]) => installRulePack(...args),
    listInstalledRulePacks: (...args: unknown[]) => listInstalledRulePacks(...args),
    setRulePackEnabled: (...args: unknown[]) => setRulePackEnabled(...args),
    removeRulePack: (...args: unknown[]) => removeRulePack(...args),
    validateSignaturePack: (...args: unknown[]) => validateSignaturePack(...args),
    installSignaturePack: (...args: unknown[]) => installSignaturePack(...args),
    listSignaturePacks: (...args: unknown[]) => listSignaturePacks(...args),
    setSignaturePackEnabled: (...args: unknown[]) => setSignaturePackEnabled(...args),
    removeSignaturePack: (...args: unknown[]) => removeSignaturePack(...args),
  },
}));

const push = vi.fn();
vi.mock("../lib/stores", () => ({
  useToastStore: (selector: (state: { push: typeof push }) => unknown) =>
    selector({ push }),
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

test("searching by a pack name or engine preserves its matching rules", async () => {
  ruleLibraryStatus.mockResolvedValue([builtInPack()]);
  listInstalledRulePacks.mockResolvedValue([]);
  render(<RuleLibraryPage />);
  await screen.findByText("eval of dynamic input");
  await userEvent.type(screen.getByLabelText("Search rules"), "source_regex");
  expect(screen.getByText("eval of dynamic input")).toBeInTheDocument();
});

test("a failed pack dialog is reported in the validation panel", async () => {
  ruleLibraryStatus.mockResolvedValue([builtInPack()]);
  listInstalledRulePacks.mockResolvedValue([]);
  open.mockRejectedValueOnce("Dialog unavailable");
  render(<RuleLibraryPage />);
  await userEvent.click(screen.getByRole("button", { name: /choose pack/i }));
  expect(await screen.findByText("Dialog unavailable")).toBeInTheDocument();
});

test("server mode validates a typed file path without a native dialog", async () => {
  transport.server = true;
  ruleLibraryStatus.mockResolvedValue([builtInPack()]);
  listInstalledRulePacks.mockResolvedValue([]);
  validateRulePack.mockResolvedValue({
    id: "rulepack.acme", name: "Acme house rules", version: "1", contentSha256: "a".repeat(64),
    ruleCount: 1, engines: ["source_regex"], fixtureCount: 2, license: "Apache-2.0", source: "Local", validation: "verified",
  });
  render(<RuleLibraryPage />);
  await userEvent.type(screen.getByLabelText("Rule pack file on server"), "/data/pack.toml");
  await userEvent.click(screen.getByRole("button", { name: "Validate pack" }));
  expect(await screen.findByText("Safe declarative pack verified")).toBeInTheDocument();
  expect(validateRulePack).toHaveBeenLastCalledWith("/data/pack.toml");
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

const preview = (overrides: Partial<SignaturePackPreview> = {}): SignaturePackPreview => ({
  kind: "yara", fileCount: 3, ignoredCount: 2, ruleCount: 12, skipped: [{ file: "bad.yar", line: 4, message: "syntax error" }],
  contentSha256: "d".repeat(64), detectedLicense: "Apache-2.0", totalBytes: 2048, protocols: null, notEvaluatedCount: 0, ...overrides,
});
const signaturePack = (overrides: Partial<InstalledSignaturePack> = {}): InstalledSignaturePack => ({
  id: "yara.acme", kind: "yara", name: "Acme YARA", version: "1.0", license: "Apache-2.0", source: "", authors: "", contentSha256: "e".repeat(64),
  fileCount: 3, ruleCount: 12, skipped: [], enabled: true, installedAt: "2026-11-18T00:00:00Z", protocols: null, notEvaluatedCount: 0, ...overrides,
});

test("a signature pack is inspected, needs a licence, installs, toggles and is removed", async () => {
  open.mockResolvedValueOnce("/rules/acme.zip");
  validateSignaturePack.mockResolvedValue(preview({ detectedLicense: null }));
  listSignaturePacks.mockResolvedValue([]);
  installSignaturePack.mockResolvedValue(signaturePack());
  render(<RuleLibraryPage />);
  await userEvent.click(await screen.findByRole("button", { name: "Choose file…" }));
  expect(open).toHaveBeenCalledWith(expect.objectContaining({ directory: false, filters: [{ name: "Signature pack", extensions: ["yar", "yara", "yaml", "yml", "zip"] }] }));
  expect(screen.getByLabelText("Pack file or folder")).toHaveValue("/rules/acme.zip");
  await userEvent.click(screen.getByRole("button", { name: "Inspect" }));
  expect(validateSignaturePack).toHaveBeenCalledWith("yara", "/rules/acme.zip");
  const group = await screen.findByRole("group", { name: "Pack preview" });
  expect(within(group).getByText("Rules that will run").nextSibling).toHaveTextContent("12");
  expect(within(group).getByText("Ignored files").nextSibling).toHaveTextContent("2");
  expect(within(group).getByText("2.0 KiB")).toBeInTheDocument();
  expect(within(group).getByText("d".repeat(64))).toBeInTheDocument();
  expect(within(group).getByText("bad.yar:4")).toBeInTheDocument();
  expect(screen.getByLabelText("Name")).toHaveValue("acme");

  await userEvent.click(screen.getByRole("button", { name: "Install pack" }));
  expect(await screen.findByText(/Enter the pack's licence before installing/)).toBeInTheDocument();
  expect(installSignaturePack).not.toHaveBeenCalled();

  await userEvent.type(screen.getByLabelText("Licence"), "MIT");
  await userEvent.type(screen.getByLabelText("Version (optional)"), "1.0");
  listSignaturePacks.mockResolvedValue([signaturePack()]);
  await userEvent.click(screen.getByRole("button", { name: "Install pack" }));
  await waitFor(() => expect(installSignaturePack).toHaveBeenCalledWith({ kind: "yara", path: "/rules/acme.zip", name: "acme", license: "MIT", version: "1.0" }));
  expect(await screen.findByText("Acme YARA")).toBeInTheDocument();
  expect(screen.queryByRole("group", { name: "Pack preview" })).not.toBeInTheDocument();
  expect(screen.getByText(/Licence Apache-2.0 · 12 rules · 3 files/)).toBeInTheDocument();

  setSignaturePackEnabled.mockResolvedValue(undefined);
  await userEvent.click(screen.getByRole("switch", { name: /Applies to scans: Acme YARA/ }));
  expect(setSignaturePackEnabled).toHaveBeenCalledWith("yara.acme", false);

  removeSignaturePack.mockResolvedValue(undefined);
  listSignaturePacks.mockResolvedValue([]);
  await userEvent.click(screen.getByRole("button", { name: "Remove Acme YARA" }));
  expect(removeSignaturePack).toHaveBeenCalledWith("yara.acme");
  expect(await screen.findByText(/No signature packs installed/)).toBeInTheDocument();
});

test("a detected licence is prefilled and Nuclei previews show protocol counts and not-evaluated templates", async () => {
  validateSignaturePack.mockResolvedValue(preview({ kind: "nuclei", ruleCount: 9, protocols: { http: 6, dns: 1, tcp: 0, ssl: 0, file: 2 }, notEvaluatedCount: 4 }));
  render(<RuleLibraryPage />);
  fireEvent.change(await screen.findByLabelText("Pack kind"), { target: { value: "nuclei" } });
  fireEvent.change(screen.getByLabelText("Pack file or folder"), { target: { value: "/t" } });
  await userEvent.click(screen.getByRole("button", { name: "Inspect" }));
  const group = await screen.findByRole("group", { name: "Pack preview" });
  expect(validateSignaturePack).toHaveBeenCalledWith("nuclei", "/t");
  expect(screen.getByLabelText("Licence")).toHaveValue("Apache-2.0");
  expect(within(group).getByText("Templates that will run")).toBeInTheDocument();
  expect(within(group).getByText("http 6 · dns 1 · file 2")).toBeInTheDocument();
  expect(within(group).getByText(/4 \(listed below; they will not run\)/)).toBeInTheDocument();
});

test("changing the path or the kind discards the inspected preview", async () => {
  validateSignaturePack.mockResolvedValue(preview());
  render(<RuleLibraryPage />);
  const path = await screen.findByLabelText("Pack file or folder");
  fireEvent.change(path, { target: { value: "/a" } });
  await userEvent.click(screen.getByRole("button", { name: "Inspect" }));
  await screen.findByRole("group", { name: "Pack preview" });
  fireEvent.change(path, { target: { value: "/b" } });
  expect(screen.queryByRole("group", { name: "Pack preview" })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Inspect" }));
  await screen.findByRole("group", { name: "Pack preview" });
  fireEvent.change(screen.getByLabelText("Pack kind"), { target: { value: "nuclei" } });
  expect(screen.queryByRole("group", { name: "Pack preview" })).not.toBeInTheDocument();
  expect(installSignaturePack).not.toHaveBeenCalled();
});

test("an inspection failure is shown inline", async () => {
  validateSignaturePack.mockRejectedValue({ code: "invalidInput", message: "Compiled .yarc files cannot be imported.", detail: null, retryable: false });
  render(<RuleLibraryPage />);
  fireEvent.change(await screen.findByLabelText("Pack file or folder"), { target: { value: "/a.yarc" } });
  await userEvent.click(screen.getByRole("button", { name: "Inspect" }));
  expect(await screen.findByText("Compiled .yarc files cannot be imported.")).toBeInTheDocument();
});

test("server mode takes a typed path and offers no native pickers", async () => {
  transport.server = true;
  validateSignaturePack.mockResolvedValue(preview());
  render(<RuleLibraryPage />);
  expect(await screen.findByLabelText("Pack path on server")).toBeInTheDocument();
  expect(screen.getByText(/Paths refer to the server's filesystem/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Choose file…" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Choose folder…" })).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Pack path on server"), { target: { value: "/data/rules" } });
  await userEvent.click(screen.getByRole("button", { name: "Inspect" }));
  expect(validateSignaturePack).toHaveBeenCalledWith("yara", "/data/rules");
  expect(open).not.toHaveBeenCalled();
});

test("a GPL-family licence gets the plain local-only notice, in the form and in the list", async () => {
  validateSignaturePack.mockResolvedValue(preview({ detectedLicense: "AGPL-3.0-only" }));
  listSignaturePacks.mockResolvedValue([signaturePack({ license: "GPL-2.0-or-later" }), signaturePack({ id: "x", name: "Other", license: "MIT" })]);
  render(<RuleLibraryPage />);
  await screen.findByText("Acme YARA");
  const notice = "This pack stays in your local data directory; oxAudit does not redistribute it.";
  expect(screen.getAllByText(notice)).toHaveLength(1);
  fireEvent.change(screen.getByLabelText("Pack file or folder"), { target: { value: "/a" } });
  await userEvent.click(screen.getByRole("button", { name: "Inspect" }));
  await screen.findByRole("group", { name: "Pack preview" });
  expect(screen.getAllByText(notice)).toHaveLength(2);
  fireEvent.change(screen.getByLabelText("Licence"), { target: { value: "MIT" } });
  expect(screen.getAllByText(notice)).toHaveLength(1);
});

test("skipped files render one page at a time and the install list shows details", async () => {
  const skipped = Array.from({ length: 60 }, (_, index) => ({ file: `rules/f${index}.yar`, line: index + 1, message: `error ${index}` }));
  validateSignaturePack.mockResolvedValue(preview({ skipped }));
  listSignaturePacks.mockResolvedValue([signaturePack({ skipped: skipped.slice(0, 3), kind: "nuclei", protocols: { http: 2, dns: 0, tcp: 0, ssl: 0, file: 0 }, notEvaluatedCount: 3, ruleCount: 2 })]);
  render(<RuleLibraryPage />);
  expect(await screen.findByText(/2 templates · 3 files · 3 not evaluated · 3 skipped/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Pack file or folder"), { target: { value: "/a" } });
  await userEvent.click(screen.getByRole("button", { name: "Inspect" }));
  const list = await screen.findByRole("list", { name: "Skipped in this pack" });
  expect(within(list).getAllByRole("listitem")).toHaveLength(25);
  await userEvent.click(screen.getByRole("button", { name: /Next page of Skipped in this pack/ }));
  expect(within(screen.getByRole("list", { name: "Skipped in this pack" })).getByText("rules/f25.yar:26")).toBeInTheDocument();
  expect(screen.getByRole("list", { name: "Skipped in Acme YARA" })).toBeInTheDocument();
});

test("the TOML copy no longer implies that only text engines ever run", async () => {
  render(<RuleLibraryPage />);
  expect(await screen.findByText(/YARA rules and Nuclei templates are separate/)).toBeInTheDocument();
});
