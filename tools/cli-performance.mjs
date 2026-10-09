#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { access, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { arch, cpus, release, tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
export function parsePeakRss(stderr, platform = process.platform) {
  const match = platform === "darwin" ? stderr.match(/^\s*(\d+)\s+maximum resident set size\s*$/m) : platform === "linux" ? stderr.match(/^\s*Maximum resident set size \(kbytes\):\s*(\d+)\s*$/m) : null;
  const value = match ? Number(match[1]) * (platform === "linux" ? 1024 : 1) : null;
  return { peakRssBytes: Number.isSafeInteger(value) && value > 0 ? value : null,
    method: ["darwin", "linux"].includes(platform) ? "/usr/bin/time" : "unavailable",
    scope: "command resource usage; not an aggregate of simultaneously resident descendant processes",
    reason: Number.isSafeInteger(value) && value > 0 ? null : ["darwin", "linux"].includes(platform) ? "maximum RSS output missing or invalid" : `peak RSS measurement is unavailable on ${platform}` };
}
/** Argument arrays, bounded output, a deadline, and owned process groups on Unix. */
export async function measureCommand({ command, args, cwd, env, timeoutMs = 120000 }) {
  let timed = false;
  if (["darwin", "linux"].includes(process.platform)) { try { await access("/usr/bin/time"); timed = true; } catch { /* explicit unknown below */ } }
  const actualCommand = timed ? "/usr/bin/time" : command;
  const actualArgs = timed ? [process.platform === "darwin" ? "-l" : "-v", command, ...args] : args;
  return await new Promise((resolve, reject) => {
    const started = performance.now(), child = spawn(actualCommand, actualArgs, { cwd, env: timed ? { ...env, LC_ALL: "C" } : env, shell: false, windowsHide: true, detached: process.platform !== "win32" });
    let stdout = "", stderr = "", bytes = 0, failure;
    const kill = (reason) => {
      failure ??= new Error(reason);
      try { if (process.platform !== "win32" && child.pid) process.kill(-child.pid, "SIGKILL"); else child.kill("SIGKILL"); } catch { /* already ended */ }
    };
    const deadline = setTimeout(() => kill("CLI performance command timed out"), timeoutMs);
    for (const [name, stream] of [["stdout", child.stdout], ["stderr", child.stderr]]) stream.on("data", (data) => {
      bytes += data.length;
      if (bytes > 32 * 1024 * 1024) return kill("CLI output exceeded 32 MiB");
      if (name === "stdout") stdout += data; else stderr += data;
    });
    child.once("error", (error) => { clearTimeout(deadline); reject(error); });
    child.once("close", (exit, signal) => {
      clearTimeout(deadline);
      if (failure || signal) reject(failure ?? new Error(`CLI terminated by ${signal}`));
      else resolve({ exit, stdout, stderr, elapsedMs: performance.now() - started, memory: timed ? parsePeakRss(stderr) : { ...parsePeakRss("", process.platform), method: "unavailable", reason: "/usr/bin/time not present or platform unsupported" } });
    });
  });
}
// Minimal deterministic ustar, containing only generated ordinary files. No
// external tar executable, extraction, or fixture execution is involved.
function tar(entries) {
  const chunks = [];
  for (const [name, content] of entries) {
    const bytes = Buffer.from(content), header = Buffer.alloc(512);
    assert.ok(Buffer.byteLength(name) < 100, "Fixture tar path too long"); header.write(name, 0);
    const octal = (offset, width, value) => header.write(value.toString(8).padStart(width - 1, "0") + "\0", offset);
    octal(100, 8, 0o644); octal(108, 8, 0); octal(116, 8, 0); octal(124, 12, bytes.length); octal(136, 12, 0);
    header.fill(32, 148, 156); header[156] = 48; header.write("ustar\0", 257); header.write("00", 263);
    const checksum = header.reduce((sum, byte) => sum + byte, 0); header.write(checksum.toString(8).padStart(6, "0") + "\0 ", 148);
    chunks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  return Buffer.concat([...chunks, Buffer.alloc(1024)]);
}
async function seedDependencyReceipt(dbPath, queryKeys, cwd, env) {
  // serde_json uses sorted object keys; hash exactly the persisted canonical
  // JSON bytes, not JS insertion order or a fabricated network exchange.
  const payload = JSON.stringify({ advisoryCoverage: "complete", queryKeys: [...queryKeys].sort(), recordCount: 0, results: {}, schemaVersion: 2 });
  const payloadFile = path.join(cwd, "synthetic-receipt.json"); await writeFile(payloadFile, payload);
  const script = `import { DatabaseSync } from 'node:sqlite'; import { readFileSync } from 'node:fs'; const [file,payloadFile,digest]=process.argv.slice(1); const payload=readFileSync(payloadFile,'utf8'); const db=new DatabaseSync(file); db.exec('CREATE TABLE IF NOT EXISTS provider_snapshots (id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, fetched_at_ms INTEGER NOT NULL, content_sha256 TEXT NOT NULL, payload_json TEXT NOT NULL)'); db.prepare('INSERT INTO provider_snapshots VALUES (?,?,?,?,?)').run('synthetic-performance-empty-receipt','osv-query',1,digest,payload); db.close();`;
  // Node 22 exposes SQLite experimentally; that capability is required only by
  // this seed step. A missing capability fails explicitly instead of going online.
  const result = await measureCommand({ command: process.execPath, args: ["--disable-warning=ExperimentalWarning", "--input-type=module", "-e", script, dbPath, payloadFile, sha(payload)], cwd, env });
  assert.equal(result.exit, 0, `Synthetic receipt seed failed: ${result.stderr}`);
}
export async function runPerformance({ cli, cliArgs = [], keep = false, tempParent = tmpdir(), env = process.env }) {
  assert.ok(cli, "Pass --cli PATH to a built CLI"); cli = await realpath(cli); await access(cli);
  const recipeBytes = await readFile(path.join(root, "benchmarks/performance/workloads.json")), recipe = JSON.parse(recipeBytes);
  const temporaryDirectory = await mkdtemp(path.join(tempParent, "oxaudit-performance-"));
  const refusedRequests = [], sockets = new Set();
  const proxy = createServer((request, response) => { refusedRequests.push({ method: request.method, target: request.url }); response.writeHead(502); response.end("Performance fixture refuses enrichment\n"); });
  proxy.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  proxy.on("connect", (request, socket) => { refusedRequests.push({ method: request.method, target: request.url }); socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); });
  try {
    await new Promise((resolve, reject) => { proxy.once("error", reject); proxy.listen(0, "127.0.0.1", resolve); });
    const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
    const childEnv = { ...env, HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, ALL_PROXY: proxyUrl, http_proxy: proxyUrl, https_proxy: proxyUrl, all_proxy: proxyUrl, NO_PROXY: "", no_proxy: "" };
    const invoke = async (args) => { const result = await measureCommand({ command: cli, args: [...cliArgs, ...args], cwd: temporaryDirectory, env: childEnv }); assert.equal(result.exit, 0, `${args[0]} expected exit 0: ${result.stderr}`); return result; };
    const version = (await invoke(["--version"])).stdout.trim();
    const source = path.join(temporaryDirectory, "source"), deps = path.join(temporaryDirectory, "deps");
    await mkdir(source); await mkdir(deps);
    const sourceText = Array.from({ length: recipe.findingsPerSourceFile }, (_, i) => `export function parse${i}(input) { return eval(input); }`).join("\n") + "\n";
    for (let i = 0; i < recipe.sourceFiles; i++) await writeFile(path.join(source, `handler-${i}.js`), sourceText);
    const status = Array.from({ length: recipe.nativePackages }, (_, i) => `Package: fixture-${i}\nStatus: install ok installed\nVersion: 1.0.0\nArchitecture: all\n\n`).join("");
    const layer = tar([["etc/os-release", 'ID=debian\nVERSION_ID="12"\n'], ["var/lib/dpkg/status", status]]);
    const archive = tar([["inner.tar", layer]]), image = tar([["manifest.json", JSON.stringify([{ Config: "config.json", RepoTags: ["fixture:local"], Layers: ["layer.tar"] }])], ["config.json", '{"architecture":"amd64","os":"linux"}'], ["layer.tar", layer]]);
    const archivePath = path.join(temporaryDirectory, "nested.tar"), imagePath = path.join(temporaryDirectory, "saved-image.tar");
    await writeFile(archivePath, archive); await writeFile(imagePath, image);
    const packages = {}, keys = [];
    for (let i = 0; i < recipe.dependencyPackages; i++) { const name = `fixture-${i}`; packages[`node_modules/${name}`] = { version: "1.0.0", resolved: `https://registry.invalid/${name}` }; keys.push(["npm", name, "1.0.0"].join("\0")); }
    const lock = JSON.stringify({ name: "owned-inert-fixture", lockfileVersion: 3, packages }); await writeFile(path.join(deps, "package-lock.json"), lock);
    const db = path.join(temporaryDirectory, "dependency.sqlite"); await invoke(["runs", "--db", db, "--json"]); await seedDependencyReceipt(db, keys, temporaryDirectory, childEnv);
    const workloads = [];
    const definitions = [
      { id: "source-findings", args: ["scan", source, "--db", path.join(temporaryDirectory, "source.sqlite")], population: { sourceFiles: recipe.sourceFiles, plantedEvalCalls: recipe.sourceFiles * recipe.findingsPerSourceFile }, fixtureSha256: sha(sourceText.repeat(recipe.sourceFiles)) },
      { id: "nested-archive", args: ["image", archivePath, "--offline"], population: { nestedTarDepth: 2, osPackages: recipe.nativePackages, inputBytes: archive.length }, fixtureSha256: sha(archive) },
      { id: "saved-image", args: ["image", imagePath, "--offline"], population: { imageLayers: 1, osPackages: recipe.nativePackages, inputBytes: image.length }, fixtureSha256: sha(image) },
      { id: "dependency-cache", args: ["deps", deps, "--offline", "--db", db], population: { lockfiles: 1, packageQueries: recipe.dependencyPackages, syntheticAdvisories: 0 }, fixtureSha256: sha(lock), advisoryEvidence: "synthetic empty test receipt; no provider accuracy claim" },
    ];
    for (const definition of definitions) {
      const reportPath = path.join(temporaryDirectory, `${definition.id}.json`);
      const measurement = await invoke([...definition.args, "--quiet", "--format", "json", "--output", reportPath]);
      const report = JSON.parse(await readFile(reportPath, "utf8")); let observed;
      if (definition.id === "source-findings") {
        assert.ok(report.summary?.filesScanned === recipe.sourceFiles && report.summary.filesSkipped === 0, "source coverage must include every owned file");
        assert.ok(Array.isArray(report.findings) && report.findings.filter((f) => f.ruleId === "js-eval").length === recipe.sourceFiles * recipe.findingsPerSourceFile && report.summary.totalFindings === report.findings.length, "source finding population changed or is incomplete");
        const fileCounts = new Map();
        for (const finding of report.findings.filter((f) => f.ruleId === "js-eval")) {
          assert.equal(typeof finding.filePath, "string", "source finding identities need their covered file");
          const name = path.basename(finding.filePath); fileCounts.set(name, (fileCounts.get(name) ?? 0) + 1);
        }
        assert.ok(fileCounts.size === recipe.sourceFiles && Array.from({ length: recipe.sourceFiles }, (_, i) => `handler-${i}.js`).every((name) => fileCounts.get(name) === recipe.findingsPerSourceFile), "source finding identities must cover every planted file and call");
        observed = { filesScanned: report.summary.filesScanned, findings: report.findings.length };
      } else if (definition.id === "dependency-cache") {
        assert.ok(report.summary?.advisoryCoverage === "complete", "dependency advisory coverage must be explicitly complete for the synthetic receipt");
        assert.ok(report.summary.packagesFound === recipe.dependencyPackages && report.summary.packagesQueried === recipe.dependencyPackages && report.dependencies?.length === recipe.dependencyPackages && report.vulnerabilities?.length === 0, "dependency cache population incomplete");
        const names = new Set(report.dependencies.map((dependency) => dependency.name));
        assert.ok(names.size === recipe.dependencyPackages && Array.from({ length: recipe.dependencyPackages }, (_, i) => `fixture-${i}`).every((name) => names.has(name)) && report.dependencies.every((dependency) => dependency.version === "1.0.0" && dependency.ecosystem === "npm"), "dependency fixture identities must include each distinct owned package");
        observed = { packagesFound: report.summary.packagesFound, packagesQueried: report.summary.packagesQueried, advisorySource: report.summary.advisorySource };
      } else {
        assert.ok(report.summary?.components === recipe.nativePackages && report.components?.length === recipe.nativePackages, "native package inventory is incomplete");
        const names = new Set(report.components.map((component) => component.product));
        assert.ok(names.size === recipe.nativePackages && Array.from({ length: recipe.nativePackages }, (_, i) => `fixture-${i}`).every((name) => names.has(name)) && report.components.every((component) => component.version === "1.0.0"), "native fixture identities must include each distinct owned package");
        observed = { components: report.components.length, vulnerabilities: report.summary.vulnerabilities, advisoryCoverage: "not measured; offline inventory fixture" };
      }
      const { args, ...receipt } = definition;
      workloads.push({ ...receipt, argv: args, elapsedMs: measurement.elapsedMs, memory: measurement.memory, exit: measurement.exit, stderr: measurement.stderr, reportPath, observed });
    }
    let toolCommit = null; try { toolCommit = execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(); } catch { /* recorded unknown */ }
    return { schemaVersion: 1, status: "passed", measuredAt: new Date().toISOString(), cli, cliVersion: version, cliSha256: sha(await readFile(cli)), toolCommit,
      environment: { platform: process.platform, architecture: arch(), osRelease: release(), cpu: cpus()[0]?.model ?? null, node: process.version },
      fixtureVersion: recipe.fixtureVersion, recipeSha256: sha(recipeBytes), temporaryDirectory, retained: keep, repetitions: 1,
      publicNetwork: "refusing loopback proxy for optional enrichment; never forwards requests; not an OS sandbox", refusedRequests, workloads,
      limitations: ["one fresh CLI process per workload, including startup, parsing and report/database writes", "single samples are observations, not statistically stable performance budgets", "source enrichment attempts are refused and included in elapsed time", "RSS is command resource usage, not aggregate process-tree resident memory", "registry pulls and real advisory provider/cache content are not measured"] };
  } finally {
    for (const socket of sockets) socket.destroy(); await new Promise((resolve) => proxy.close(resolve));
    if (!keep) await rm(temporaryDirectory, { recursive: true, force: true });
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2), options = {};
    for (let i = 0; i < args.length; i++) { const key = args[i]; assert.ok(["--cli", "--output", "--keep"].includes(key) && options[key] === undefined, "Invalid/duplicate option"); options[key] = key === "--keep" ? true : args[++i]; }
    assert.ok(options["--cli"] && options["--output"], "Usage: cli-performance.mjs --cli PATH --output FILE [--keep]");
    const receipt = await runPerformance({ cli: options["--cli"], keep: options["--keep"] });
    await writeFile(options["--output"], JSON.stringify(receipt, null, 2) + "\n"); console.log(`${receipt.status}: ${receipt.workloads.length} workload measurements written to ${options["--output"]}`);
  } catch (error) { console.error(`CLI performance failed: ${error.message}`); process.exitCode = 1; }
}
