import { canonicalMetadata, canonicalPage } from "../../tests/fixtures/pagedResults";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../lib/api";
import { useAppStore } from "../lib/stores";
import { useScanWorkStore } from "../features/project-home/coordinator";
import { TemplateScanPage, parseTargets } from "./TemplateScan";
import type { InstalledSignaturePack, TemplateMatchRow, TemplateScanResult } from "../lib/types";

const handlers = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
const transport = vi.hoisted(() => ({ live: true }));
vi.mock("../lib/events", () => ({ listen: async (name: string, callback: (event: { payload: unknown }) => void) => { handlers.set(name, callback); return () => handlers.delete(name); } }));
vi.mock("../lib/transport", async importOriginal => ({ ...await importOriginal<typeof import("../lib/transport")>(), get liveTargetsAllowed() { return transport.live; } }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const pack = (overrides: Partial<InstalledSignaturePack> = {}): InstalledSignaturePack => ({
  id: "nuclei.acme", kind: "nuclei", name: "Acme templates", version: "1", license: "MIT", source: "", authors: "", contentSha256: "a".repeat(64),
  fileCount: 2, ruleCount: 5, skipped: [], enabled: true, installedAt: "2026-11-18T00:00:00Z", protocols: { http: 4, dns: 0, tcp: 0, ssl: 0, file: 1 }, notEvaluatedCount: 0, ...overrides,
});
const liveMatch = (overrides: Partial<TemplateMatchRow> = {}): TemplateMatchRow => ({
  id: "t1", templateId: "exposed-panel", ruleId: "nuclei.acme/exposed-panel", name: "Exposed admin panel", severity: "medium", tags: ["panel"], pack: "nuclei.acme", protocol: "http",
  matchedAt: "https://staging.example.com/admin", lines: [], matcherNames: ["status-ok", "title"], extracted: [["version", ["1.2.3"]]],
  classification: { cveId: ["CVE-2099-0001"], cweId: ["CWE-200"], cvssScore: 5.3 }, description: "An admin panel answers without a login.",
  reference: ["https://example.com/advisory", "javascript:alert(1)"], remediation: "Restrict access to the panel.",
  exchange: { protocol: "http", target: "staging.example.com", request: "GET /admin HTTP/1.1\nAuthorization: [REDACTED]", responseExcerpt: "HTTP/1.1 200 OK\n\n<title>Admin</title>", responseTruncated: true }, ...overrides,
});
const result = (overrides: Partial<TemplateScanResult> = {}): TemplateScanResult => ({
  runId: "run-t", mode: "targets", target: "1 live target", state: "completed", matches: [liveMatch()], matchesDropped: 0, notEvaluated: [], notEvaluatedDropped: 0,
  packs: [{ id: "nuclei.acme", name: "Acme templates", license: "MIT", contentSha256: "a".repeat(64), templateCount: 5 }], templatesLoaded: 5, templatesRun: 4, filesScanned: 0, bytesScanned: 0,
  skipped: [], requestsSent: 17, requestsRefused: 2, refusedHosts: ["evil.example.net"], resolved: [{ host: "staging.example.com", addresses: ["10.0.0.5"] }],
  unreachableTargets: [{ target: "down.example.com", reason: "no route to host" }], authorization: { acknowledged: true, statement: "ENG-42", acknowledgedAtMs: Date.UTC(2026, 10, 18, 12) }, notes: [], durationMs: 9, ...overrides,
});
const fileMatch = (): TemplateMatchRow => liveMatch({
  id: "f1", templateId: "hardcoded-token", name: "Hardcoded token", protocol: "file", matchedAt: "config/app.env", filePath: "config/app.env",
  lines: [{ line: 3, startColumn: 7, endColumn: 20, text: "TOKEN=abc123" }], exchange: null, matcherNames: [], extracted: [], reference: [], classification: { cveId: [], cweId: [], cvssScore: null },
});

beforeEach(() => {
  vi.restoreAllMocks();
  handlers.clear();
  transport.live = true;
  useAppStore.setState({ page: "template-scan", pageStatus: {}, activeProject: null, selectedProject: null, exportHandoff: null });
  useScanWorkStore.setState({ active: null, check: null, backend: { active: null, recent: [] }, lastTargets: {}, recoveryError: null });
  vi.spyOn(api, "listSignaturePacks").mockResolvedValue([pack()]);
  vi.spyOn(api, "listCanonicalRuns").mockResolvedValue([]);
  vi.spyOn(api, "scanWorkStatus").mockResolvedValue({ active: null, recent: [] });
  vi.spyOn(api, "cancelScanWork").mockResolvedValue(true);
  vi.spyOn(api, "loadCanonicalProjectionMetadata").mockImplementation(async () => { throw new Error("no saved run"); });
});

const runButton = () => screen.getByRole("button", { name: /Run (live|template) scan/ });
async function liveMode() {
  await screen.findByText(/Packs \(1 of 1 selected\)/);
  await userEvent.click(screen.getByRole("radio", { name: "Live targets" }));
}

test("parseTargets trims, drops blanks and removes repeats without validating", () => {
  expect(parseTargets(" a.example \r\n\n b.example\na.example\n10.0.0.0/24 ")).toEqual(["a.example", "b.example", "10.0.0.0/24"]);
});

test("the mode control switches between a local path and live targets", async () => {
  render(<TemplateScanPage />);
  expect(await screen.findByLabelText("Template target")).toBeInTheDocument();
  expect(screen.queryByLabelText("Targets")).not.toBeInTheDocument();
  await liveMode();
  expect(screen.getByLabelText("Targets")).toBeInTheDocument();
  expect(screen.queryByLabelText("Template target")).not.toBeInTheDocument();
  expect(screen.getByText(/send network requests to the listed targets only/)).toBeInTheDocument();
  expect(screen.getByText(/limits come from Settings, Live scanning/)).toBeInTheDocument();
  expect(screen.getByRole("switch", { name: "Include intrusive templates" })).not.toBeChecked();
  expect(screen.getByText(/Templates tagged dos never run/)).toBeInTheDocument();
});

test("without enabled Nuclei packs the page points to Rule Library and cannot run", async () => {
  vi.mocked(api.listSignaturePacks).mockResolvedValue([pack({ kind: "yara", id: "y" })]);
  render(<TemplateScanPage />);
  expect(await screen.findByText("No Nuclei templates are enabled")).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Template target"), { target: { value: "/scan" } });
  expect(runButton()).toBeDisabled();
  await userEvent.click(screen.getByRole("button", { name: "Open Rule Library" }));
  expect(useAppStore.getState().page).toBe("rule-library");
});

test("a live run needs targets and a fresh authorization, sends it, and resets it after the run", async () => {
  const scan = vi.spyOn(api, "scanTemplates").mockResolvedValue(result());
  const setItem = vi.spyOn(Storage.prototype, "setItem");
  const saveSettings = vi.spyOn(api, "saveSettings");
  render(<TemplateScanPage />);
  await liveMode();
  expect(runButton()).toBeDisabled();
  const targets = screen.getByLabelText("Targets");
  fireEvent.change(targets, { target: { value: " https://staging.example.com \n\nhttps://staging.example.com\n10.0.0.5:8080" } });
  expect(screen.getByText(/2 targets\./)).toBeInTheDocument();
  expect(runButton()).toBeDisabled();
  const ack = screen.getByRole("checkbox", { name: "I am authorized to test these targets" });
  await userEvent.click(ack);
  expect(runButton()).toBeEnabled();
  fireEvent.change(screen.getByLabelText("Statement (optional)"), { target: { value: " ENG-42 " } });
  fireEvent.change(screen.getByLabelText("Only tags"), { target: { value: "cve, exposure ,cve" } });
  fireEvent.change(screen.getByLabelText("Exclude tags"), { target: { value: "tech" } });
  await userEvent.click(screen.getByRole("checkbox", { name: "high" }));
  await userEvent.click(screen.getByRole("switch", { name: "Include intrusive templates" }));
  await userEvent.click(runButton());
  await waitFor(() => expect(scan).toHaveBeenCalled());
  const operationId = expect.any(String);
  expect(scan).toHaveBeenCalledWith({
    targets: ["https://staging.example.com", "10.0.0.5:8080"], authorization: { acknowledged: true, statement: "ENG-42" }, includeIntrusive: true,
    tags: ["cve", "exposure"], excludeTags: ["tech"], severities: ["high"], operationId,
  });
  expect(await screen.findByRole("list", { name: "Template matches" })).toBeInTheDocument();
  expect(screen.getByRole("checkbox", { name: "I am authorized to test these targets" })).not.toBeChecked();
  expect(runButton()).toBeDisabled();
  expect(setItem).not.toHaveBeenCalledWith(expect.stringMatching(/author/i), expect.anything());
  expect(JSON.stringify(setItem.mock.calls)).not.toMatch(/acknowledged|authorized/i);
  expect(saveSettings).not.toHaveBeenCalled();
});

test("editing the target list clears the authorization", async () => {
  render(<TemplateScanPage />);
  await liveMode();
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: "a.example" } });
  const ack = screen.getByRole("checkbox", { name: "I am authorized to test these targets" });
  await userEvent.click(ack);
  expect(ack).toBeChecked();
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: "a.example\nb.example" } });
  expect(ack).not.toBeChecked();
  expect(runButton()).toBeDisabled();
  await userEvent.click(ack);
  await userEvent.click(screen.getByRole("radio", { name: "Local path" }));
  await userEvent.click(screen.getByRole("radio", { name: "Live targets" }));
  expect(screen.getByRole("checkbox", { name: "I am authorized to test these targets" })).not.toBeChecked();
});

test("a backend scope error naming the bad target is shown inline and the authorization is cleared", async () => {
  vi.spyOn(api, "scanTemplates").mockRejectedValue({ code: "invalidInput", message: "Target \"999.1.1.1/40\" is not a URL, host, IP address or CIDR range.", detail: null, retryable: false });
  render(<TemplateScanPage />);
  await liveMode();
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: "999.1.1.1/40" } });
  await userEvent.click(screen.getByRole("checkbox", { name: "I am authorized to test these targets" }));
  await userEvent.click(runButton());
  expect(await screen.findByRole("alert")).toHaveTextContent(/999\.1\.1\.1\/40/);
  expect(screen.getByText("Template scan unavailable")).toBeInTheDocument();
  expect(screen.getByRole("checkbox", { name: "I am authorized to test these targets" })).not.toBeChecked();
});

test("live targets are unavailable on a server without the flag and nothing is sent", async () => {
  transport.live = false;
  const scan = vi.spyOn(api, "scanTemplates");
  render(<TemplateScanPage />);
  await liveMode();
  expect(screen.getByText("Live targets are turned off on this server")).toBeInTheDocument();
  expect(screen.getByText(/--allow-live-targets/)).toBeInTheDocument();
  expect(screen.queryByLabelText("Targets")).not.toBeInTheDocument();
  expect(runButton()).toBeDisabled();
  await userEvent.click(runButton());
  expect(scan).not.toHaveBeenCalled();
});

test("a local path run sends only the path and filters, with progress for its own operation", async () => {
  let finish!: (value: TemplateScanResult) => void;
  const scan = vi.spyOn(api, "scanTemplates").mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  render(<TemplateScanPage />);
  await screen.findByText(/Packs/);
  fireEvent.change(screen.getByLabelText("Template target"), { target: { value: "/scan" } });
  await userEvent.click(runButton());
  const operationId = useScanWorkStore.getState().active!.operationId;
  expect(scan).toHaveBeenCalledWith({ path: "/scan", operationId });
  await act(async () => handlers.get("template://progress")?.({ payload: { operationId: "other", message: "stale", done: 1, total: 2, requestsSent: 99, matches: 0 } }));
  expect(screen.queryByText("stale")).not.toBeInTheDocument();
  await act(async () => handlers.get("template://progress")?.({ payload: { operationId, message: "Completed 2 of 8 template-target checks; 11 request(s) sent, 1 match(es)", done: 2, total: 8, requestsSent: 11, matches: 1 } }));
  expect(screen.getByText("11 requests sent · 1 matches")).toBeInTheDocument();
  await act(async () => finish(result({ mode: "path", target: "/scan", matches: [fileMatch()], authorization: null, requestsSent: 0, requestsRefused: 0, refusedHosts: [], resolved: [], unreachableTargets: [], filesScanned: 3 })));
  const list = await screen.findByRole("list", { name: "Template matches" });
  await userEvent.click(within(list).getByRole("button", { name: /Hardcoded token/ }));
  const lines = screen.getByRole("list", { name: "Matched lines" });
  expect(within(lines).getByText("TOKEN=abc123")).toBeInTheDocument();
  expect(within(lines).getByText("Line 3, columns 7–20")).toBeInTheDocument();
  expect(screen.queryByRole("region", { name: "Scope" })).not.toBeInTheDocument();
});

test("live results show detail, scope and the stored exchange; hostile response content stays inert text", async () => {
  vi.spyOn(api, "scanTemplates").mockResolvedValue(result({
    matches: [liveMatch({ exchange: { protocol: "http", target: "staging.example.com", request: "GET / HTTP/1.1", responseExcerpt: "<img src=x onerror=alert(1)><script>window.pwned=1</script>", responseTruncated: true } })],
  }));
  render(<TemplateScanPage />);
  await liveMode();
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: "https://staging.example.com" } });
  await userEvent.click(screen.getByRole("checkbox", { name: "I am authorized to test these targets" }));
  await userEvent.click(runButton());
  const list = await screen.findByRole("list", { name: "Template matches" });
  expect(within(list).getByText("status-ok, title", { exact: false })).toBeInTheDocument();
  await userEvent.click(within(list).getByRole("button", { name: /Exposed admin panel/ }));
  const detail = screen.getByRole("region", { name: "Match detail" });
  expect(within(detail).getByText("An admin panel answers without a login.")).toBeInTheDocument();
  expect(within(detail).getByText("CVE-2099-0001")).toBeInTheDocument();
  expect(within(detail).getByText("CWE-200")).toBeInTheDocument();
  expect(within(detail).getByText("5.3")).toBeInTheDocument();
  expect(within(detail).getByText("Restrict access to the panel.")).toBeInTheDocument();
  expect(within(detail).getByText("1.2.3")).toBeInTheDocument();
  expect(within(detail).getByRole("link", { name: "https://example.com/advisory" })).toHaveAttribute("href", "https://example.com/advisory");
  expect(within(detail).queryByRole("link", { name: /javascript:/ })).not.toBeInTheDocument();
  expect(within(detail).getByText("javascript:alert(1)")).toBeInTheDocument();
  const response = within(detail).getByLabelText("Response excerpt");
  expect(response.textContent).toBe("<img src=x onerror=alert(1)><script>window.pwned=1</script>");
  expect(response.querySelector("img, script")).toBeNull();
  expect(detail.querySelector("img, script")).toBeNull();
  expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
  expect(within(detail).getByText(/response was truncated/)).toBeInTheDocument();
  const scope = screen.getByRole("region", { name: "Scope" });
  expect(within(scope).getByText("17")).toBeInTheDocument();
  expect(within(scope).getByText("evil.example.net")).toBeInTheDocument();
  expect(within(scope).getByText("10.0.0.5")).toBeInTheDocument();
  expect(within(scope).getByText("down.example.com")).toBeInTheDocument();
  expect(within(scope).getByText("no route to host")).toBeInTheDocument();
  expect(within(scope).getByText("Statement: ENG-42")).toBeInTheDocument();
  expect(within(scope).getByText("2026-11-18T12:00:00.000Z")).toBeInTheDocument();
});

test("no match reports the not-evaluated count, groups it by reason, and an incomplete run is a warning", async () => {
  vi.spyOn(api, "scanTemplates").mockResolvedValue(result({
    matches: [], state: "incomplete", notes: ["request cap reached"],
    notEvaluated: [
      { templateId: "a", pack: "nuclei.acme", file: "a.yaml", reason: "headless templates are not run" },
      { templateId: "b", pack: "nuclei.acme", file: "b.yaml", reason: "headless templates are not run" },
      { templateId: "", pack: "nuclei.acme", file: "c.yaml", reason: "file did not parse" },
    ],
  }));
  render(<TemplateScanPage />);
  await liveMode();
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: "a.example" } });
  await userEvent.click(screen.getByRole("checkbox", { name: "I am authorized to test these targets" }));
  await userEvent.click(runButton());
  expect(await screen.findByText("No template matched.")).toBeInTheDocument();
  expect(screen.getByText(/3 templates or checks were not evaluated; they did not run\./)).toBeInTheDocument();
  expect(screen.getByText("This run is incomplete")).toBeInTheDocument();
  expect(screen.getAllByText(/request cap reached/).length).toBeGreaterThan(0);
  const section = screen.getByRole("region", { name: "Not evaluated" });
  expect(within(section).getByText("2 · headless templates are not run")).toBeInTheDocument();
  expect(within(section).getByText("1 · file did not parse")).toBeInTheDocument();
  expect(within(section).getByText(/\(file did not load as a template\)/)).toBeInTheDocument();
  fireEvent.change(within(section).getByLabelText("Search not evaluated"), { target: { value: "parse" } });
  expect(within(within(section).getByRole("list", { name: "Templates and checks that were not evaluated" })).getAllByRole("listitem")).toHaveLength(1);
  expect(useAppStore.getState().pageStatus["template-scan"]?.tone).not.toBe("success");
  expect(document.body.textContent ?? "").not.toMatch(/\b(clean|safe|secure)\b/i);
});

test("the Run button is disabled with nothing selected and Export Center opens the run", async () => {
  vi.spyOn(api, "scanTemplates").mockResolvedValue(result({ mode: "path", authorization: null }));
  render(<TemplateScanPage />);
  await screen.findByText(/Packs/);
  await userEvent.click(screen.getByRole("checkbox", { name: /Acme templates/ }));
  fireEvent.change(screen.getByLabelText("Template target"), { target: { value: "/scan" } });
  expect(runButton()).toBeDisabled();
  await userEvent.click(screen.getByRole("checkbox", { name: /Acme templates/ }));
  await userEvent.click(runButton());
  await userEvent.click(await screen.findByRole("button", { name: "Open Export Center" }));
  expect(useAppStore.getState().exportHandoff).toEqual({ runId: "run-t" });
});

test("cancel goes through the coordinator", async () => {
  vi.spyOn(api, "scanTemplates").mockImplementation(() => new Promise(() => {}));
  render(<TemplateScanPage />);
  await screen.findByText(/Packs/);
  fireEvent.change(screen.getByLabelText("Template target"), { target: { value: "/scan" } });
  await userEvent.click(runButton());
  const operationId = useScanWorkStore.getState().active!.operationId;
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  await waitFor(() => expect(api.cancelScanWork).toHaveBeenCalledWith(operationId));
});

test("a saved local run reopens with paged matches and a paged Not evaluated list", async () => {
  const saved = result({
    runId: "saved-t", mode: "path", target: "/scan", authorization: null, requestsSent: 0, requestsRefused: 0, refusedHosts: [], resolved: [], unreachableTargets: [],
    matches: Array.from({ length: 55 }, (_, index) => ({ ...fileMatch(), id: `f${index}`, name: `Finding ${String(index).padStart(2, "0")}` })),
    notEvaluated: Array.from({ length: 60 }, (_, index) => ({ templateId: `t${index}`, pack: "nuclei.acme", file: `t${index}.yaml`, reason: index % 2 ? "dsl function not implemented" : "headless templates are not run" })),
  });
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([{ id: "saved-t", kind: "template", targetLabel: "/scan", state: "completed", attempt: 1, createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] }]);
  vi.mocked(api.loadCanonicalProjectionMetadata).mockImplementation(async () => canonicalMetadata(saved));
  const page = vi.spyOn(api, "loadCanonicalProjectionPage").mockImplementation((async (_id: string, section: never, query: never) => canonicalPage(saved, section, query)) as never);
  render(<TemplateScanPage />);
  fireEvent.change(await screen.findByLabelText("Template target"), { target: { value: "/scan" } });
  const list = await screen.findByRole("list", { name: "Template matches" });
  await waitFor(() => expect(within(list).getAllByRole("listitem")).toHaveLength(50));
  await waitFor(() => expect(page).toHaveBeenCalledWith("saved-t", "notEvaluated", expect.objectContaining({ limit: 50 })));
  const section = await screen.findByRole("region", { name: "Not evaluated" });
  expect(await within(section).findByText("Not evaluated (60)")).toBeInTheDocument();
  await waitFor(() => expect(within(section).getAllByRole("listitem").length).toBeGreaterThanOrEqual(50));
  expect(within(section).getByLabelText("Reasons on this page")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Next page of template matches" }));
  await waitFor(() => expect(within(screen.getByRole("list", { name: "Template matches" })).getAllByRole("listitem")).toHaveLength(5));
});
