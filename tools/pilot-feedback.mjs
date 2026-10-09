#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const tasks = ["installation", "first-actionable-finding", "verified-resolution", "malformed-dependency", "restart-export", "ci-adoption"];
const requiredTasks = tasks.slice(0, 5);
const text = (value) => typeof value === "string" && value.trim().length > 0 && value.length <= 10000;
function exactKeys(value, allowed, label) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert.ok(Object.keys(value).every((key) => allowed.includes(key)), `Unknown ${label} field`);
}
function validDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) return false;
  const date = new Date(value); return Number.isFinite(date.valueOf()) && date.toISOString().slice(0, 19) === value.slice(0, 19);
}
export function blankFeedback() {
  return { schemaVersion: 1, participant: { id: null, relationship: null, consentToShare: false },
    session: { observedAt: null, os: null, architecture: null, appVersion: null, artifactSha256: null, editor: null }, observations: [] };
}
export function validateFeedback(form) {
  exactKeys(form, ["schemaVersion", "participant", "session", "observations", "status", "capturedAt", "acceptance"], "feedback");
  assert.equal(form.schemaVersion, 1, "Expected feedback schemaVersion 1");
  exactKeys(form.participant, ["id", "relationship", "consentToShare"], "participant");
  exactKeys(form.session, ["observedAt", "os", "architecture", "appVersion", "artifactSha256", "editor"], "session");
  assert.ok(Array.isArray(form.observations) && form.observations.length <= 100, "Observations must be an array of at most 100 records");
  assert.equal(typeof form.participant.consentToShare, "boolean", "Consent must be explicit");
  const empty = form.observations.length === 0;
  for (const key of ["id", "relationship"]) assert.ok((empty && form.participant[key] === null) || text(form.participant[key]), `Missing participant ${key}`);
  if (form.participant.relationship !== null) assert.ok(["external", "maintainer", "internal"].includes(form.participant.relationship), "Invalid participant relationship");
  for (const key of ["os", "architecture", "appVersion", "editor"]) assert.ok((empty && form.session[key] === null) || text(form.session[key]), `Missing session ${key}`);
  assert.ok((empty && form.session.observedAt === null) || validDate(form.session.observedAt), "Invalid observation date");
  assert.ok((empty && form.session.artifactSha256 === null) || /^[0-9a-f]{64}$/.test(form.session.artifactSha256 ?? ""), "Invalid artifact SHA-256");
  if (!empty) assert.equal(form.participant.consentToShare, true, "Capture requires participant consent to share this record");
  const seen = new Set();
  for (const observation of form.observations) {
    exactKeys(observation, ["task", "outcome", "elapsedSeconds", "evidence", "notes", "runIds", "coverageProof"], "observation");
    assert.ok(tasks.includes(observation.task) && !seen.has(observation.task), "Invalid or duplicate task"); seen.add(observation.task);
    assert.ok(["completed", "blocked", "not-evaluated"].includes(observation.outcome), "Invalid task outcome");
    assert.ok(observation.elapsedSeconds === null || (Number.isFinite(observation.elapsedSeconds) && observation.elapsedSeconds >= 0), "Invalid elapsed time");
    if (observation.outcome === "completed") assert.ok(Number.isFinite(observation.elapsedSeconds) && observation.elapsedSeconds >= 0, "Completed tasks require measured elapsed seconds");
    assert.ok(text(observation.notes), "Record observed notes or actual limitation");
    assert.ok(Array.isArray(observation.evidence) && observation.evidence.every(text), "Invalid evidence references");
    if (observation.outcome !== "not-evaluated") assert.ok(observation.evidence.length > 0, "Observed tasks require evidence references");
    assert.ok(Array.isArray(observation.runIds) && observation.runIds.every(text), "Invalid run IDs");
    if (observation.task === "first-actionable-finding" && observation.outcome === "completed") assert.ok(observation.runIds.length > 0, "Finding observation needs a canonical run ID");
    if (observation.task === "verified-resolution" && observation.outcome === "completed") {
      const proof = observation.coverageProof;
      exactKeys(proof, ["state", "compatible", "coveredFile", "previousRunId", "currentRunId"], "coverage proof");
      assert.ok(proof.state === "completed" && proof.compatible === true && text(proof.coveredFile) && text(proof.previousRunId) && text(proof.currentRunId) && proof.currentRunId !== proof.previousRunId, "Resolution requires compatible completed coverage");
      assert.ok(observation.runIds.includes(proof.previousRunId) && observation.runIds.includes(proof.currentRunId), "Resolution proof run IDs must match the observation");
    } else assert.ok(observation.coverageProof === undefined, "Coverage proof is only valid for a verified resolution");
  }
  const completedTasks = form.observations.filter((o) => o.outcome === "completed").map((o) => o.task);
  const acceptance = { complete: requiredTasks.every((task) => completedTasks.includes(task)), scope: "this participant's five required desktop tasks only", completedTasks };
  if (form.acceptance !== undefined) assert.deepEqual(form.acceptance, acceptance, "Acceptance must be derived from actual task observations");
  if (form.status !== undefined) assert.equal(form.status, empty ? "prepared" : "observed", "Status disagrees with observations");
  if (form.capturedAt !== undefined) assert.ok(validDate(form.capturedAt) && !empty, "Invalid capture date");
  return { status: empty ? "prepared" : "observed", acceptance };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
try {
  const [command, ...args] = process.argv.slice(2), options = {};
  assert.ok(["init", "validate", "capture"].includes(command), "Usage: pilot-feedback.mjs init --output FILE | validate --input FILE | capture --input FILE --output FILE");
  assert.ok(args.length % 2 === 0, "Options require values");
  for (let i = 0; i < args.length; i += 2) { assert.ok(["--input", "--output"].includes(args[i]) && args[i + 1] && !options[args[i]], "Invalid/duplicate option"); options[args[i]] = args[i + 1]; }
  if (command === "init") {
    assert.ok(options["--output"] && !options["--input"], "init requires only --output");
    await writeFile(options["--output"], JSON.stringify(blankFeedback(), null, 2) + "\n", { flag: "wx" });
    console.log("prepared: blank participant form, 0 observations");
  } else {
    assert.ok(options["--input"] && (command === "capture" ? options["--output"] : !options["--output"]), "Invalid options for command");
    const form = JSON.parse(await readFile(options["--input"], "utf8")), validated = validateFeedback(form);
    if (command === "capture") {
      assert.equal(validated.status, "observed", "Blank preparation cannot be captured as participant evidence");
      await writeFile(options["--output"], JSON.stringify({ ...form, ...validated, capturedAt: new Date().toISOString() }, null, 2) + "\n", { flag: "wx" });
    }
    console.log(`${validated.status}: ${form.observations.length} observations; required desktop tasks complete: ${validated.acceptance.complete}`);
  }
} catch (error) { console.error(`Pilot feedback refused: ${error.message}`); process.exitCode = 2; }
}
