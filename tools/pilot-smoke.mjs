#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { access, copyFile, mkdir, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const fixtures = fileURLToPath(new URL("../examples/pilot/", import.meta.url));

function run(command, args, env, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, cwd, shell: false, windowsHide: true });
    let stdout = "", stderr = "", bytes = 0;
    const timeout = setTimeout(() => {
      child.kill(); reject(new Error(`CLI timed out: ${args[0]}`));
    }, 120_000);
    const capture = (stream) => (data) => {
      bytes += data.length;
      if (bytes > 16 * 1024 * 1024) { child.kill(); reject(new Error("CLI output exceeded 16 MiB")); return; }
      if (stream === "stdout") stdout += data; else stderr += data;
    };
    child.stdout.on("data", capture("stdout")); child.stderr.on("data", capture("stderr"));
    child.on("error", (error) => { clearTimeout(timeout); reject(error); });
    child.on("close", (code, signal) => {
      clearTimeout(timeout);
      if (signal) reject(new Error(`CLI terminated by ${signal}`));
      else resolve({ code, stdout, stderr });
    });
  });
}

/** Scan only copied inert fixtures with the caller's CLI, never repository scripts. */
export async function runPilot({ cli, cliArgs = [], keep = false, tempParent = tmpdir(), env = process.env }) {
  assert.ok(cli, "Pass the path to a built CLI with --cli PATH");
  cli = await realpath(cli);
  await access(cli);
  const temporaryDirectory = await mkdtemp(path.join(tempParent, "oxaudit-pilot-"));
  const refusedRequests = [];
  const proxy = createServer((request, response) => {
    refusedRequests.push({ method: request.method, target: request.url });
    response.writeHead(502); response.end("Optional network enrichment refused by pilot smoke\n");
  });
  proxy.on("connect", (request, socket) => {
    refusedRequests.push({ method: request.method, target: request.url });
    socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
  });
  const commands = [];
  try {
    await new Promise((resolve, reject) => {
      proxy.once("error", reject); proxy.listen(0, "127.0.0.1", resolve);
    });
    const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
    // reqwest honours these proxy settings. Copy the environment, including an
    // explicit empty NO_PROXY, so neither user bypasses nor parent mutations
    // can defeat this smoke's optional-enrichment boundary.
    const childEnv = { ...env, HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, ALL_PROXY: proxyUrl,
      http_proxy: proxyUrl, https_proxy: proxyUrl, all_proxy: proxyUrl, NO_PROXY: "", no_proxy: "" };
    const project = path.join(temporaryDirectory, "project");
    const malformed = path.join(temporaryDirectory, "malformed");
    await mkdir(project); await mkdir(malformed);
    await copyFile(path.join(fixtures, "vulnerable/handler.js"), path.join(project, "handler.js"));
    await copyFile(path.join(fixtures, "malformed-dependency/package-lock.json"), path.join(malformed, "package-lock.json"));
    const db = path.join(temporaryDirectory, "runs.sqlite");
    const invoke = async (label, args, code = 0) => {
      const result = await run(cli, [...cliArgs, ...args], childEnv, temporaryDirectory);
      commands.push({ label, argv: [cli, ...cliArgs, ...args], exit: result.code, stderr: result.stderr });
      assert.equal(result.code, code, `${label}: expected exit ${code}, got ${result.code}\n${result.stderr}`);
      return result;
    };
    const readJson = async (file) => JSON.parse(await readFile(file, "utf8"));
    const sourceRunIds = [];
    const sourceDatabases = [];
    const scan = async (label, file, args, expectedCode, vulnerable) => {
      const db = path.join(temporaryDirectory, `source-${sourceRunIds.length + 1}.sqlite`);
      const before = refusedRequests.length;
      const result = await invoke(label, ["scan", project, "--db", db, "--format", "json", "--output", file, ...args], expectedCode);
      const report = await readJson(file);
      assert.equal(report.summary?.filesScanned, 1, `${label}: expected coverage of the copied source file`);
      assert.equal(report.summary?.filesSkipped, 0, `${label}: source coverage must not skip files`);
      assert.ok(Array.isArray(report.findings), `${label}: missing findings array`);
      assert.equal(report.summary.totalFindings, report.findings.length, `${label}: inconsistent report counts`);
      assert.equal(report.findings.some((finding) => finding.ruleId === "js-eval"), vulnerable, `${label}: unexpected js-eval finding state`);
      if (vulnerable) assert.ok(refusedRequests.slice(before).some((request) => request.method === "CONNECT" && request.target === "www.cisa.gov:443"), `${label}: optional CISA request did not reach the refusing proxy; cannot establish this CLI's network boundary`);
      const listed = await invoke(`${label} history`, ["runs", "--kind", "source", "--db", db, "--limit", "1", "--json"]);
      const rows = JSON.parse(listed.stdout);
      assert.equal(rows.length, 1, `${label}: expected one completed source run`);
      const latest = rows[0];
      assert.ok(latest.kind === "source" && latest.state === "completed" && typeof latest.id === "string" && latest.id.length > 0, `${label}: expected a completed source run with canonical id`);
      assert.equal(latest.targetLabel, path.basename(project), `${label}: history target label mismatch`);
      assert.ok(!sourceRunIds.includes(latest.id), `${label}: history returned a stale run`);
      sourceRunIds.push(latest.id);
      sourceDatabases.push(db);
      return { report, runId: latest.id, db, stderr: result.stderr };
    };
    const baseline = path.join(temporaryDirectory, "baseline.json");
    const first = await scan("source finding", baseline, ["--fail-on", "high"], 1, true);
    const sarifFile = path.join(temporaryDirectory, "source.sarif");
    await invoke("SARIF export", ["export", "--db", first.db, "--run", first.runId, "--format", "sarif", "--output", sarifFile]);
    const sarif = await readJson(sarifFile);
    assert.equal(sarif.version, "2.1.0");
    assert.ok(sarif.runs?.some((run) => run.results?.some((finding) => finding.ruleId === "js-eval")), "SARIF must contain the source js-eval finding");
    await scan("unchanged baseline gate", path.join(temporaryDirectory, "unchanged.json"), ["--baseline", baseline, "--fail-on-new", "high"], 0, true);
    await copyFile(path.join(fixtures, "corrected/handler.js"), path.join(project, "handler.js"));
    const correctedFile = path.join(temporaryDirectory, "corrected.json");
    const corrected = await scan("corrected source", correctedFile, ["--baseline", baseline, "--fail-on-new", "high"], 0, false);
    assert.match(corrected.stderr, /no longer observed.*coverage unverified/, "report-only baseline absence must not claim verified resolution");
    await copyFile(path.join(fixtures, "vulnerable/handler.js"), path.join(project, "handler.js"));
    await scan("introduced source gate", path.join(temporaryDirectory, "introduced.json"), ["--baseline", correctedFile, "--fail-on-new", "high"], 1, true);
    await invoke("malformed dependency coverage", ["deps", malformed, "--offline", "--db", db, "--format", "json", "--output", path.join(temporaryDirectory, "malformed.json")], 3);
    for (const [index, sourceDb] of sourceDatabases.entries()) {
      const history = JSON.parse((await invoke("durable source history", ["runs", "--kind", "source", "--db", sourceDb, "--limit", "20", "--json"])).stdout);
      assert.ok(history.some((row) => row.id === sourceRunIds[index] && row.state === "completed" && row.kind === "source"), `Missing durable source run ${sourceRunIds[index]}`);
    }
    return { status: "passed", cli, temporaryDirectory, retained: keep,
      sourceRunIds, correctedEvidence: "no longer observed (coverage unverified)",
      optionalEnrichment: "unavailable; requests refused without supplying provider data",
      refusedRequests, commands };
  } finally {
    await new Promise((resolve) => proxy.close(resolve));
    if (!keep) await rm(temporaryDirectory, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    assert.ok(args.length >= 2 && args[0] === "--cli" && args[1] && args.slice(2).every((arg) => arg === "--keep"), "Usage: node tools/pilot-smoke.mjs --cli /absolute/path/to/oxaudit-cli [--keep]");
    console.log(JSON.stringify(await runPilot({ cli: args[1], keep: args.includes("--keep") }), null, 2));
  } catch (error) { console.error(`Pilot smoke failed: ${error.message}`); process.exitCode = 1; }
}
