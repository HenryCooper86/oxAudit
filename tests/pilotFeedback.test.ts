import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

test("feedback validators can be imported without running the capture CLI", () => {
  const invoked = spawnSync(process.execPath, ["--input-type=module", "--eval", "import { blankFeedback, validateFeedback } from './tools/pilot-feedback.mjs'; console.log(validateFeedback(blankFeedback()).status);"], { encoding: "utf8" });
  assert.equal(invoked.status, 0, invoked.stderr);
  assert.equal(invoked.stdout.trim(), "prepared");
  assert.equal(invoked.stderr, "");
});

async function exercise(change?: (data: any) => void) {
  const owned = await mkdtemp(path.join(tmpdir(), "oxaudit-feedback-test-"));
  const invoke = (args: string[]) => spawnSync(process.execPath, ["tools/pilot-feedback.mjs", ...args], { encoding: "utf8" });
  try {
    const input = path.join(owned, "form.json"), output = path.join(owned, "captured.json");
    const init = invoke(["init", "--output", input]);
    assert.equal(init.status, 0, init.stderr);
    const form = JSON.parse(await readFile(input, "utf8"));
    if (change) { change(form); await writeFile(input, JSON.stringify(form)); }
    const validation = invoke(["validate", "--input", input]);
    const capture = invoke(["capture", "--input", input, "--output", output]);
    let captured; try { captured = JSON.parse(await readFile(output, "utf8")); } catch { /* rejected capture must write nothing */ }
    return { form, validation, capture, captured };
  } finally { await rm(owned, { recursive: true, force: true }); }
}
// Synthetic test-only records exercise the input contract; they are never
// participant feedback or pilot acceptance evidence.
const observed = (form: any) => {
  Object.assign(form.participant, { id: "engineer-01", relationship: "external", consentToShare: true });
  Object.assign(form.session, { observedAt: "2026-10-09T10:00:00Z", os: "macOS", architecture: "arm64", appVersion: "0.1.0", artifactSha256: "a".repeat(64), editor: "VS Code" });
  form.observations.push({ task: "first-actionable-finding", outcome: "completed", elapsedSeconds: 84, evidence: ["local:screenshot-01"], notes: "Located the evaluation call.", runIds: ["run-01"] });
};
test("blank pilot form validates preparation and cannot be captured as observed evidence", async () => {
  const result = await exercise();
  assert.deepEqual(result.form.observations, []);
  assert.equal(result.form.participant.id, null);
  assert.equal(result.validation.status, 0, result.validation.stderr);
  assert.match(result.validation.stdout, /prepared.*0 observations/);
  assert.equal(result.capture.status, 2);
  assert.equal(result.captured, undefined);
});
test("observation input capture retains attribution, evidence, timing and acceptance scope", async () => {
  const result = await exercise(observed);
  assert.equal(result.capture.status, 0, result.capture.stderr);
  assert.equal(result.captured.status, "observed");
  assert.equal(result.captured.observations[0].elapsedSeconds, 84);
  assert.equal(result.captured.participant.relationship, "external");
  assert.equal(result.captured.acceptance.complete, false);
});
for (const [name, change] of [
  ["negative timing", (f: any) => { f.observations[0].elapsedSeconds = -1; }],
  ["missing evidence", (f: any) => { f.observations[0].evidence = []; }],
  ["fabricated acceptance", (f: any) => { f.acceptance = { complete: true }; }],
  ["unknown task", (f: any) => { f.observations[0].task = "magic"; }],
  ["invalid date", (f: any) => { f.session.observedAt = "2026-02-30T00:00:00Z"; }],
  ["missing consent", (f: any) => { f.participant.consentToShare = false; }],
  ["verified resolution without coverage proof", (f: any) => { f.observations[0].task = "verified-resolution"; }],
] as const) test(`feedback rejects ${name}`, async () => {
  const result = await exercise((f) => { observed(f); change(f); });
  assert.equal(result.validation.status, 2, result.validation.stderr);
  assert.equal(result.capture.status, 2, result.capture.stderr);
  assert.equal(result.captured, undefined);
});
test("blocked tasks retain a real error without a made-up duration or completed outcome", async () => {
  const result = await exercise((f) => { observed(f); f.observations[0] = { task: "installation", outcome: "blocked", elapsedSeconds: null, evidence: ["local:installer-error"], notes: "Installer rejected the artifact.", runIds: [] }; });
  assert.equal(result.capture.status, 0, result.capture.stderr);
  assert.equal(result.captured.acceptance.complete, false);
});
test("only all five observed required tasks with compatible resolution proof complete this participant's acceptance", async () => {
  const result = await exercise((f) => {
    observed(f);
    for (const task of ["installation", "malformed-dependency", "restart-export"]) f.observations.push({ task, outcome: "completed", elapsedSeconds: 12, evidence: [`local:${task}`], notes: "Observed task outcome.", runIds: [] });
    f.observations.push({ task: "verified-resolution", outcome: "completed", elapsedSeconds: 52, evidence: ["local:coverage-receipt"], notes: "Compatible completed coverage recorded by UI.", runIds: ["run-01", "run-02"], coverageProof: { state: "completed", compatible: true, coveredFile: "handler.js", previousRunId: "run-01", currentRunId: "run-02" } });
  });
  assert.equal(result.capture.status, 0, result.capture.stderr);
  assert.equal(result.captured.acceptance.complete, true);
  assert.equal(result.captured.acceptance.scope, "this participant's five required desktop tasks only");
});
