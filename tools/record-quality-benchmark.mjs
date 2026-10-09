#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { COMMIT } from "./fetch-external-benchmark.mjs";
import { validateQualityEnvelope } from "./compare-quality-benchmark.mjs";
import { measureCommand } from "./cli-performance.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const git = (directory, args) => execFileSync("git", ["-C", directory, ...args], { encoding: "utf8" }).trim();
export async function recordQuality({ cli, cliArgs = [], corpus, output, expectedCommit = COMMIT }) {
  cli = await realpath(cli); corpus = await realpath(corpus); output = path.resolve(output);
  const pin = git(corpus, ["rev-parse", "HEAD"]);
  assert.equal(pin, expectedCommit, "External corpus pin does not match the required commit");
  assert.equal(git(corpus, ["status", "--porcelain", "--untracked-files=all"]), "", "External corpus is modified; a commit ID alone cannot prove fixture identity");
  await mkdir(path.dirname(output), { recursive: true }); await mkdir(output);
  const requests = [], sockets = new Set();
  const proxy = createServer((request, response) => { requests.push({ method: request.method, target: request.url }); response.writeHead(502); response.end("Quality measurement refuses provider requests\n"); });
  proxy.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  proxy.on("connect", (request, socket) => { requests.push({ method: request.method, target: request.url }); socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); });
  try {
    await new Promise((resolve, reject) => { proxy.once("error", reject); proxy.listen(0, "127.0.0.1", resolve); });
    const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
    const env = { ...process.env, HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, ALL_PROXY: proxyUrl, http_proxy: proxyUrl, https_proxy: proxyUrl, all_proxy: proxyUrl, NO_PROXY: "", no_proxy: "" };
    const raw = path.join(output, "raw.json");
    const measured = await measureCommand({ command: cli, args: [...cliArgs, "external-benchmark", "--path", corpus, "--json", "--output", raw], env, cwd: root, timeoutMs: 600000 });
    await writeFile(path.join(output, "command.json"), JSON.stringify({ exit: measured.exit, elapsedMs: measured.elapsedMs, memory: measured.memory, stderr: measured.stderr, refusedRequests: requests }, null, 2) + "\n");
    assert.equal(measured.exit, 0, `External benchmark failed: ${measured.stderr}`);
    const report = JSON.parse(await readFile(raw, "utf8"));
    const result = { schemaVersion: 1, provenance: { benchmarkCommit: pin, evaluator: "owasp-java-cwe-v1", expectationsSha256: sha(await readFile(path.join(corpus, "expectedresults-1.2.csv"))),
      toolCommit: git(root, ["rev-parse", "HEAD"]), toolWorkingTreeDirty: git(root, ["status", "--porcelain"]).length > 0, cliSha256: sha(await readFile(cli)), measuredAt: new Date().toISOString() }, report };
    validateQualityEnvelope(result);
    await writeFile(path.join(output, "result.json"), JSON.stringify(result, null, 2) + "\n"); return result;
  } finally { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => proxy.close(resolve)); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2), options = {};
    assert.equal(args.length, 6, "Usage: record-quality-benchmark.mjs --cli PATH --corpus DIR --output NEW_DIR");
    for (let i = 0; i < args.length; i += 2) { assert.ok(["--cli", "--corpus", "--output"].includes(args[i]) && args[i + 1] && !options[args[i]], "Invalid/duplicate option"); options[args[i]] = args[i + 1]; }
    assert.ok(options["--cli"] && options["--corpus"] && options["--output"], "Missing options");
    const result = await recordQuality({ cli: options["--cli"], corpus: options["--corpus"], output: options["--output"] });
    console.log(`Measured ${result.report.cases} labelled cases at ${result.provenance.benchmarkCommit}; raw and provenance JSON retained`);
  } catch (error) { console.error(`Quality recording failed: ${error.message}`); process.exitCode = 2; }
}
