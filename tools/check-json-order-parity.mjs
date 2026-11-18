#!/usr/bin/env node
// Differential check: two builds of the same oxaudit-cli source must print the
// same bytes for the same input.
//
//   ON  - default features; the `yara-x` dependency enables serde_json's
//         `preserve_order`, so `serde_json::Map` keeps insertion order.
//   OFF - `--no-default-features --features grammars-all`; `serde_json::Map`
//         is a sorted BTreeMap, as in every release up to 0.3.3.
//
// Both binaries run the same offline scenario (each in a fresh workspace with
// its own databases) and every stdout, stderr, exit code and written file is
// compared. Only genuinely volatile VALUES are replaced (random ids,
// timestamps, durations); output is never parsed and re-serialised, so a
// difference in key order, number formatting or whitespace fails the check.
//
// Usage:
//   node tools/check-json-order-parity.mjs --on <cli> --off <cli> [--only TEXT] [--keep] [--verbose] [--dump DIR]
//
// See docs/dependency-maintenance.md ("JSON key order and preserve_order").

import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile, copyFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const repo = fileURLToPath(new URL("../", import.meta.url));
const fixtures = path.join(repo, "examples/pilot");

// ---------------------------------------------------------------------------
// Arguments

function parseArguments(argv) {
  const options = { on: null, off: null, only: null, keep: false, verbose: false, dump: null };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--on") options.on = argv[++index];
    else if (arg === "--off") options.off = argv[++index];
    else if (arg === "--only") options.only = argv[++index];
    else if (arg === "--dump") options.dump = argv[++index];
    else if (arg === "--keep") options.keep = true;
    else if (arg === "--verbose") options.verbose = true;
    else throw new Error(`unknown argument ${arg}`);
  }
  if (!options.on || !options.off) {
    throw new Error("Usage: node tools/check-json-order-parity.mjs --on <cli> --off <cli> [--only TEXT] [--keep] [--verbose] [--dump DIR]");
  }
  return options;
}

// ---------------------------------------------------------------------------
// Process helpers

function runProcess(command, args, { env, cwd, input }) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, cwd, shell: false, windowsHide: true });
    const out = [], err = [];
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error(`timed out: ${args.join(" ")}`)); }, 180_000);
    child.stdout.on("data", (d) => out.push(d));
    child.stderr.on("data", (d) => err.push(d));
    child.on("error", (e) => { clearTimeout(timer); reject(e); });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (signal) reject(new Error(`terminated by ${signal}: ${args.join(" ")}`));
      else resolve({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err) });
    });
    if (input !== undefined) child.stdin.end(input); else child.stdin.end();
  });
}

function git(cwd, env, ...args) {
  const result = spawnSync("git", args, { cwd, env, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  return result.stdout;
}

// ---------------------------------------------------------------------------
// A stored-method zip, enough for the advisory dump the CLI ingests.

function crc32(buffer) {
  if (typeof zlib.crc32 === "function") return zlib.crc32(buffer) >>> 0;
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function makeZip(entries) {
  const locals = [], centrals = [];
  let offset = 0;
  for (const [name, text] of entries) {
    const nameBytes = Buffer.from(name);
    const data = Buffer.from(text);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8); local.writeUInt16LE(0, 10); local.writeUInt16LE(0x21, 12);
    local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26); local.writeUInt16LE(0, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8); central.writeUInt16LE(0, 10); central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0x21, 14); central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28); central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, data);
    centrals.push(central, nameBytes);
    offset += local.length + nameBytes.length + data.length;
  }
  const centralBytes = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBytes, end]);
}

const advisoryDump = () => makeZip([
  ["GHSA-parity-0001.json", JSON.stringify({
    id: "GHSA-parity-0001", modified: "2024-05-01T00:00:00Z", published: "2024-04-01T00:00:00Z",
    summary: "parity fixture advisory", details: "A fixture advisory used to compare builds.",
    aliases: ["CVE-2099-1234"],
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
    references: [{ type: "ADVISORY", url: "https://example.invalid/advisory/1" }],
    database_specific: { zeta: 1, alpha: { omega: true, beta: [3, 2, 1] }, cwe_ids: ["CWE-79"] },
    affected: [{
      package: { ecosystem: "npm", name: "example" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
    }],
  })],
  ["GHSA-parity-0002.json", JSON.stringify({
    id: "GHSA-parity-0002", modified: "2024-06-01T00:00:00Z", summary: "second fixture advisory",
    aliases: ["CVE-2099-5678"],
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" }],
    affected: [{
      package: { ecosystem: "npm", name: "lodash" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "4.0.0" }, { fixed: "4.17.21" }] }],
    }],
  })],
]);

// ---------------------------------------------------------------------------
// Fixtures

const VULN_JS = "vulnerable/handler.js";

async function put(file, text) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, text);
}

async function materialise(W, gitEnv) {
  const src = path.join(W, "src");
  await mkdir(src, { recursive: true });
  await copyFile(path.join(fixtures, VULN_JS), path.join(src, "handler.js"));
  await put(path.join(src, "app.py"), [
    "import os, pickle, subprocess, yaml", "",
    "def run(cmd):", "    os.system(cmd)", "    subprocess.call(cmd, shell=True)", "",
    "def load(blob, text):", "    yaml.load(text)", "    return pickle.loads(blob)", "",
  ].join("\n"));
  await put(path.join(src, "Vuln.java"),
    "class Vuln { void go(String input) throws Exception { Runtime.getRuntime().exec(input); } }\n");
  await put(path.join(src, "deploy.env"),
    "AWS_ACCESS_KEY_ID=AKIAZ9X8W7U6T5S4R3Q2\nGITHUB_TOKEN=ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\n");
  await put(path.join(src, "marker.js"), "function go() { parityMarkerCall(payload); }\n");

  const deps = path.join(W, "deps");
  await put(path.join(deps, "package-lock.json"), JSON.stringify({
    name: "parity", version: "1.0.0", lockfileVersion: 3,
    packages: {
      "": { name: "parity", version: "1.0.0", dependencies: { example: "1.0.0", lodash: "4.17.20" } },
      "node_modules/example": { version: "1.0.0", license: "MIT" },
      "node_modules/lodash": { version: "4.17.20", license: "MIT", dependencies: { "left-pad": "1.3.0" } },
      "node_modules/left-pad": { version: "1.3.0", license: "WTFPL", dev: true },
      "node_modules/gpl-thing": { version: "2.1.0", license: "GPL-3.0-only" },
    },
  }, null, 2) + "\n");
  await put(path.join(deps, "requirements.txt"), "flask==2.0.0\nrequests==2.25.0\n");
  await put(path.join(deps, "Cargo.lock"), [
    "# This file is automatically @generated by Cargo.", "version = 3", "",
    "[[package]]", 'name = "parity"', 'version = "0.1.0"', 'dependencies = [', ' "serde",', "]", "",
    "[[package]]", 'name = "serde"', 'version = "1.0.100"',
    'source = "registry+https://github.com/rust-lang/crates.io-index"',
    'checksum = "' + "a".repeat(64) + '"', "",
  ].join("\n"));
  await put(path.join(deps, "go.mod"), "module example.invalid/parity\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n");
  await put(path.join(deps, ".oxaudit/component-policy.json"), JSON.stringify({
    version: 1,
    licenses: { deny: ["category:strong-copyleft"], warn: ["WTFPL"], unknown: "warn" },
    vulnerabilities: { deny: "critical", warn: "medium" },
    components: [{ ecosystem: "npm", package: "left-pad", decision: "rejected", reason: "Unmaintained" }],
  }, null, 2) + "\n");
  await mkdir(path.join(W, "malformed"), { recursive: true });
  await copyFile(path.join(fixtures, "malformed-dependency/package-lock.json"), path.join(W, "malformed/package-lock.json"));

  const img = path.join(W, "img");
  await put(path.join(img, "etc/os-release"), 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n');
  await put(path.join(img, "var/lib/dpkg/status"), [
    "Package: openssl", "Status: install ok installed", "Architecture: amd64", "Version: 3.0.11-1~deb12u1", "Description: SSL", "",
    "Package: zlib1g", "Status: install ok installed", "Architecture: amd64", "Version: 1:1.2.13.dfsg-1", "Description: zlib", "", "",
  ].join("\n"));
  await put(path.join(img, "usr/bin/tool"), "#!/bin/sh\necho tool\n");

  const pack = path.join(W, "pack");
  for (const name of ["pack.toml", "positive.txt", "negative.txt"]) {
    await mkdir(pack, { recursive: true });
    await copyFile(path.join(fixtures, "rule-pack", name), path.join(pack, name));
  }

  const vex = path.join(W, "vex");
  await put(path.join(vex, "openvex.json"), JSON.stringify({
    "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.invalid/vex/parity-1",
    author: "Parity Author", timestamp: "2024-01-01T00:00:00Z", version: 1,
    statements: [{
      vulnerability: { name: "CVE-2099-1234" },
      products: [{ "@id": "pkg:npm/example@1.0.0" }],
      status: "not_affected", justification: "vulnerable_code_not_in_execute_path",
    }],
  }, null, 2) + "\n");

  await put(path.join(vex, "report.sarif"), JSON.stringify({
    version: "2.1.0", $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: { driver: { name: "Parity Scanner", version: "1.0", rules: [{ id: "PARITY-1", name: "Parity rule", shortDescription: { text: "Fixture rule" } }] } },
      results: [{
        ruleId: "PARITY-1", level: "error", message: { text: "Fixture finding" },
        locations: [{ physicalLocation: { artifactLocation: { uri: "src/handler.js" }, region: { startLine: 4, startColumn: 10 } } }],
      }, {
        ruleId: "PARITY-1", level: "note", message: { text: "Second fixture finding" },
        locations: [{ physicalLocation: { artifactLocation: { uri: "src/app.py" }, region: { startLine: 9 } } }],
      }],
    }],
  }, null, 2) + "\n");
  await put(path.join(vex, "cyclonedx-vex.json"), JSON.stringify({
    bomFormat: "CycloneDX", specVersion: "1.6", version: 1,
    components: [{ "bom-ref": "component_parity_example", type: "library", name: "example", version: "1.0.0", purl: "pkg:npm/example@1.0.0" }],
    vulnerabilities: [{
      id: "GHSA-parity-0001", analysis: { state: "not_affected", justification: "code_not_reachable", detail: "Fixture statement." },
      affects: [{ ref: "component_parity_example" }],
    }],
  }, null, 2) + "\n");

  const repoDir = path.join(W, "repo");
  await mkdir(path.join(repoDir, "src"), { recursive: true });
  git(repoDir, gitEnv, "init", "-q", "-b", "main");
  git(repoDir, gitEnv, "config", "user.email", "parity@example.invalid");
  git(repoDir, gitEnv, "config", "user.name", "Parity");
  await put(path.join(repoDir, "src/deploy.sh"), "#!/bin/sh\nexport AWS_ACCESS_KEY_ID=AKIAZ9X8W7U6T5S4R3Q2\n");
  await put(path.join(repoDir, "src/app.js"), "console.log('clean');\n");
  git(repoDir, gitEnv, "add", ".");
  git(repoDir, gitEnv, "commit", "-q", "-m", "leak");
  await rm(path.join(repoDir, "src/deploy.sh"));
  git(repoDir, gitEnv, "add", "-A");
  git(repoDir, gitEnv, "commit", "-q", "-m", "remove leak");
  await put(path.join(repoDir, "src/staged.env"), "GITHUB_TOKEN=ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\n");
  git(repoDir, gitEnv, "add", "src/staged.env");
}

// ---------------------------------------------------------------------------
// Normalisation: replace volatile VALUES only.

// 64-hex digests that are derived from a random run id (artifact ids,
// correlation hashes, fingerprints) change on every run. Which contexts those
// are is learned from the data: a context (the JSON key, or the `name_` prefix,
// right before the digest) is volatile when ON and a second run of ON disagree
// about the digests in it. Digests in other contexts (file and content hashes)
// are never masked.
const DIGEST = /("([A-Za-z0-9_]+)"\s*:\s*"|([a-z]+_))([0-9a-f]{64})(?![0-9a-f])/g;

function digestsByContext(text) {
  const found = new Map();
  for (const match of text.matchAll(DIGEST)) {
    const context = match[2] ?? match[3];
    if (!found.has(context)) found.set(context, new Set());
    found.get(context).add(match[4]);
  }
  return found;
}

function volatileContexts(onTexts, on2Texts) {
  const a = new Map(), b = new Map();
  for (const [map, texts] of [[a, onTexts], [b, on2Texts]]) {
    for (const text of texts) for (const [context, set] of digestsByContext(text)) {
      if (!map.has(context)) map.set(context, new Set());
      for (const digest of set) map.get(context).add(digest);
    }
  }
  const volatile = new Set();
  for (const context of new Set([...a.keys(), ...b.keys()])) {
    const left = a.get(context) ?? new Set(), right = b.get(context) ?? new Set();
    if ([...left].some((d) => !right.has(d)) || [...right].some((d) => !left.has(d))) volatile.add(context);
  }
  return volatile;
}

const UUID = /(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])/gi;

// `numbered`: ids become <uuid-N> by order of first appearance within a binary's
// run (so an id reused across outputs must line up); otherwise a flat <uuid>.
function makeNormaliser(numbered, volatile = new Set()) {
  const uuids = new Map();
  return (input) => {
    let text = input;
    text = text.replace(UUID, (id) => {
      if (!numbered) return "<uuid>";
      const key = id.toLowerCase();
      if (!uuids.has(key)) uuids.set(key, `<uuid-${uuids.size + 1}>`);
      return uuids.get(key);
    });
    text = text.replace(DIGEST, (whole, lead, key, prefix) => volatile.has(key ?? prefix) ? `${lead}<digest>` : whole);
    text = text.replace(/(?<!\d)1\d{12}(?!\d)/g, "<epoch-ms>");
    text = text.replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g, "<time>");
    text = text.replace(/("[A-Za-z_]*(?:Ms|Millis|Epoch|Elapsed|Duration)[A-Za-z_]*"\s*:\s*)\d+(?:\.\d+)?/g, "$1<ms>");
    text = text.replace(/\b(in|took|elapsed)\s+\d+(?:\.\d+)?\s*(ms|s)\b/g, "$1 <n> $2");
    text = text.replace(/\/D:\d{14}[^)]*\)/g, "/D:<pdf-date>)");
    text = text.replace(/\/ID\s*\[[^\]]*\]/g, "/ID [<pdf-id>]");
    return text;
  };
}

// ---------------------------------------------------------------------------
// Order-insensitive comparison, used ONLY for output that is already unstable
// between two runs of the same binary (see `unstable` below). The stored graph
// is read back `ORDER BY id`, and ids are random UUIDs, so list order in
// graph-backed reports changes from run to run in every build. For those
// outputs byte equality is impossible, so we compare (a) the multiset of
// lines and (b) the multiset of "object path -> key order" signatures read
// off the text with a small scanner (nothing is parsed into JS objects or
// re-serialised). A key reordering changes (b) even though it cannot change (a).

function keyOrderSignatures(text) {
  const signatures = [];
  const stack = []; // { type: "object"|"array", path, keys: [], expectKey }
  let index = 0;
  const top = () => stack[stack.length - 1];
  while (index < text.length) {
    const ch = text[index];
    if (ch === '"') {
      let end = index + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === "\\" ? 2 : 1;
      const token = text.slice(index + 1, end);
      const frame = top();
      if (frame && frame.type === "object" && frame.expectKey) { frame.keys.push(token); frame.expectKey = false; frame.lastKey = token; }
      index = end + 1;
      continue;
    }
    if (ch === "{" || ch === "[") {
      const parent = top();
      const segment = parent ? (parent.type === "object" ? `.${parent.lastKey}` : "[]") : "$";
      stack.push({ type: ch === "{" ? "object" : "array", path: (parent ? parent.path : "") + segment, keys: [], expectKey: ch === "{" });
    } else if (ch === "}" || ch === "]") {
      const frame = stack.pop();
      if (frame && frame.type === "object") signatures.push(`${frame.path}: ${frame.keys.join(",")}`);
    } else if (ch === ",") {
      const frame = top();
      if (frame && frame.type === "object") frame.expectKey = true;
    }
    index += 1;
  }
  return signatures.sort();
}

// Extra masks for outputs that are unstable between runs of one binary: SPDX
// element numbers follow the (random-id) component order.
const weakMask = (text) => text.replace(/SPDXRef-Package-\d+/g, "SPDXRef-Package-<n>");

function weaklyEqual(a, b) {
  a = weakMask(a); b = weakMask(b);
  const lines = (t) => t.split("\n").sort().join("\n");
  if (lines(a) !== lines(b)) return { equal: false, why: "line multiset", left: lines(a), right: lines(b) };
  const looksJson = /^\s*[[{]/.test(a);
  if (looksJson) {
    const left = keyOrderSignatures(a).join("\n"), right = keyOrderSignatures(b).join("\n");
    if (left !== right) return { equal: false, why: "object key order", left, right };
  }
  return { equal: true };
}

// ---------------------------------------------------------------------------
// The scenario. Every call goes through `step`, so both binaries execute the
// same sequence and results line up by position and label.

const SCAN_FORMATS = ["text", "json", "sarif", "oxaudit-json", "cyclonedx", "spdx", "openvex", "cyclonedx-vex",
  "github-issues-csv", "jira-csv", "junit", "gitlab-code-quality", "gitlab-dependency-scanning"];
const DEPS_FORMATS = SCAN_FORMATS;
const EXPORT_FORMATS = ["sarif", "oxaudit-json", "cyclonedx", "spdx", "openvex", "cyclonedx-vex", "github-issues-csv", "jira-csv"];

async function scenario({ cli, W, env, dumpUrl, filter }) {
  const results = [];
  const db = (name) => path.join(W, "db", `${name}.sqlite`);
  const out = (name) => path.join(W, "out", name);

  async function step(label, args, options = {}) {
    if (filter && !label.includes(filter)) { results.push({ label, skipped: true }); return null; }
    const { cwd = W, files = [], input, ok = [0, 1] } = options;
    const run = await runProcess(cli, args, { env, cwd, input });
    const fileContents = {};
    for (const file of files) {
      try { fileContents[path.relative(W, file)] = await readFile(file); }
      catch { fileContents[path.relative(W, file)] = Buffer.from("<missing>"); }
    }
    const record = { label, args: args.map((a) => path.relative(W, a).startsWith("..") ? a : a), code: run.code,
      stdout: run.stdout, stderr: run.stderr, files: fileContents, expected: ok.includes(run.code) };
    results.push(record);
    return record;
  }
  const json = (record) => { try { return JSON.parse(record.stdout.toString("utf8")); } catch { return null; } };

  // The project the desktop and CLI scan: source findings in several languages.
  const src = path.join(W, "src");
  const deps = path.join(W, "deps");
  const repoDir = path.join(W, "repo");

  // --- scan: every output format, each against a fresh database
  for (const format of SCAN_FORMATS) {
    const accepted = { openvex: [3], "gitlab-dependency-scanning": [2] }[format] ?? [0, 1];
    await step(`scan --format ${format}`, ["scan", src, "--db", db(`scan-${format}`), "--format", format], { ok: accepted });
  }
  const scanFile = out("scan.json");
  await step("scan --format json --output FILE --fail-on high", ["scan", src, "--db", db("scan-main"), "--format", "json", "--output", scanFile, "--fail-on", "high"], { files: [scanFile] });
  const runs = json(await step("runs --kind source --json", ["runs", "--kind", "source", "--db", db("scan-main"), "--json", "--limit", "5"]));
  const sourceRunId = runs?.[0]?.id;
  await step("scan --baseline --fail-on-new", ["scan", src, "--db", db("scan-baseline"), "--format", "json", "--baseline", scanFile, "--fail-on-new", "high"]);
  await step("scan --sarif-uri-prefix", ["scan", src, "--format", "sarif", "--sarif-uri-prefix", "services/api"]);
  await step("scan --rule-pack-file", ["scan", src, "--db", db("scan-pack"), "--format", "json", "--rule-pack-file", path.join(W, "pack/pack.toml")]);
  await step("scan --no-secrets --format sarif", ["scan", src, "--format", "sarif", "--no-secrets"]);
  await step("scan --staged text", ["scan", "--staged", "--quiet"], { cwd: repoDir, ok: [0, 1] });
  await step("scan --staged json", ["scan", "--staged", "--format", "json"], { cwd: repoDir });

  // --- runs and export of the stored source run
  await step("runs (project summary, text)", ["runs", "--db", db("scan-main")]);
  await step("runs (project summary, json)", ["runs", "--db", db("scan-main"), "--json"]);
  await step("runs --kind all (text)", ["runs", "--kind", "all", "--db", db("scan-main")]);
  await step("runs --kind all --json", ["runs", "--kind", "all", "--db", db("scan-main"), "--json"]);
  for (const format of EXPORT_FORMATS) {
    await step(`export source run --format ${format}`, ["export", "--db", db("scan-main"), "--run", sourceRunId ?? "missing", "--format", format], { ok: [0, 1, 2, 3] });
  }
  await step("export source run sarif --sarif-uri-prefix", ["export", "--db", db("scan-main"), "--run", sourceRunId ?? "missing", "--format", "sarif", "--sarif-uri-prefix", "a/b"]);

  // --- history of a git repository
  for (const format of ["text", "json", "sarif", "oxaudit-json", "cyclonedx", "github-issues-csv", "jira-csv"]) {
    await step(`history --format ${format}`, ["history", repoDir, "--db", db(`history-${format}`), "--format", format], { ok: [0, 1, 2, 3] });
  }
  await step("history --baseline", ["history", repoDir, "--format", "json", "--baseline", out("history.json")], { ok: [0, 1, 2, 3] });
  const historyFile = out("history.json");
  await step("history --format json --output FILE", ["history", repoDir, "--db", db("history-main"), "--format", "json", "--output", historyFile], { files: [historyFile] });
  const historyRuns = json(await step("runs --kind history --json", ["runs", "--kind", "history", "--db", db("history-main"), "--json"]));
  const historyRunId = historyRuns?.[0]?.id;
  for (const format of ["sarif", "oxaudit-json", "github-issues-csv"]) {
    await step(`export history run --format ${format}`, ["export", "--db", db("history-main"), "--run", historyRunId ?? "missing", "--format", format], { ok: [0, 1, 2, 3] });
  }

  // --- advisory database built from a local dump, then offline matching
  await step("advisory-db update", ["advisory-db", "update", "--db", db("advisories"), "--source", dumpUrl]);
  await step("advisory-db update --json", ["advisory-db", "update", "--db", db("advisories-json"), "--source", dumpUrl, "--json"]);
  await step("advisory-db status", ["advisory-db", "status", "--db", db("advisories")]);
  await step("advisory-db status --json", ["advisory-db", "status", "--db", db("advisories"), "--json"]);

  const adv = db("advisories");
  for (const format of DEPS_FORMATS) {
    await step(`deps --offline --advisory-db --format ${format}`, ["deps", deps, "--offline", "--advisory-db", adv, "--db", db(`deps-${format}`), "--format", format]);
  }
  const depsFile = out("deps.json");
  await step("deps --format json --output FILE", ["deps", deps, "--offline", "--advisory-db", adv, "--db", db("deps-main"), "--format", "json", "--output", depsFile, "--fail-on", "high"], { files: [depsFile] });
  await step("deps --baseline --fail-on-new", ["deps", deps, "--offline", "--advisory-db", adv, "--format", "json", "--baseline", depsFile, "--fail-on-new", "high"]);
  await step("deps --sarif-uri-prefix", ["deps", deps, "--offline", "--advisory-db", adv, "--format", "sarif", "--sarif-uri-prefix", "pkg"]);
  await step("deps (malformed lockfile)", ["deps", path.join(W, "malformed"), "--offline", "--format", "json", "--db", db("deps-malformed")], { ok: [0, 1, 2, 3] });
  await step("deps --offline without receipt", ["deps", deps, "--offline", "--format", "json"], { ok: [0, 1, 2, 3] });
  const depsRuns = json(await step("runs --kind dependencies --json", ["runs", "--kind", "dependencies", "--db", db("deps-main"), "--json"]));
  const depsRunId = depsRuns?.[0]?.id;
  for (const format of EXPORT_FORMATS) {
    await step(`export deps run --format ${format}`, ["export", "--db", db("deps-main"), "--run", depsRunId ?? "missing", "--format", format]);
  }

  // --- sca and portfolio over the stored dependency run
  for (const format of ["text", "json", "junit", "gitlab-code-quality", "gitlab-dependency-scanning"]) {
    await step(`sca --format ${format}`, ["sca", deps, "--offline", "--advisory-db", adv, "--no-release-facts", "--db", db(`sca-${format}`), "--format", format], { ok: [0, 1, 2, 3] });
  }
  const notices = out("NOTICES.md");
  await step("sca --notices", ["sca", deps, "--offline", "--advisory-db", adv, "--no-release-facts", "--report-only", "--notices", notices, "--db", db("sca-main")], { files: [notices] });
  await step("portfolio summary", ["portfolio", "summary", "--db", db("sca-main")]);
  await step("portfolio summary --json", ["portfolio", "summary", "--db", db("sca-main"), "--json"]);
  await step("portfolio components", ["portfolio", "components", "--db", db("sca-main")]);
  await step("portfolio components --json", ["portfolio", "components", "--db", db("sca-main"), "--json"]);
  await step("portfolio where-used", ["portfolio", "where-used", "--db", db("sca-main"), "lodash"]);
  await step("portfolio where-used --json", ["portfolio", "where-used", "--db", db("sca-main"), "--json", "lodash"]);
  await step("portfolio history", ["portfolio", "history", "--db", db("sca-main"), "--target", deps]);
  await step("portfolio history --json", ["portfolio", "history", "--db", db("sca-main"), "--target", deps, "--json"]);

  // --- monitor: re-match stored inventories against the advisory database
  await step("monitor --format text", ["monitor", "--db", db("deps-main"), "--advisory-db", adv]);
  await step("monitor --format json", ["monitor", "--db", db("deps-main"), "--advisory-db", adv, "--format", "json"]);

  // --- image (a directory tree with an OS package database)
  for (const format of ["text", "json", "sarif", "oxaudit-json", "cyclonedx", "spdx", "openvex", "cyclonedx-vex"]) {
    await step(`image --offline --format ${format}`, ["image", path.join(W, "img"), "--offline", "--advisory-db", adv, "--db", db(`image-${format}`), "--format", format], { ok: [0, 1, 2, 3] });
  }

  // --- rule packs
  const packDb = db("rulepacks");
  await step("rule-pack install", ["rule-pack", "install", "--db", packDb, path.join(W, "pack/pack.toml")]);
  await step("rule-pack list", ["rule-pack", "list", "--db", packDb]);
  await step("rule-pack list --json", ["rule-pack", "list", "--db", packDb, "--json"]);
  await step("scan --rule-pack --rule-pack-db", ["scan", src, "--db", db("scan-installed-pack"), "--format", "json", "--rule-pack", "rulepack.parity", "--rule-pack-db", packDb]);
  await step("rule-pack disable", ["rule-pack", "disable", "--db", packDb, "rulepack.parity"]);
  await step("rule-pack list --json (disabled)", ["rule-pack", "list", "--db", packDb, "--json"]);
  await step("rule-pack enable", ["rule-pack", "enable", "--db", packDb, "rulepack.parity"]);
  await step("rule-pack remove", ["rule-pack", "remove", "--db", packDb, "rulepack.parity"]);

  // --- import and VEX trust flow
  const importDb = db("claims");
  const sarifExport = out("claims.sarif");
  await step("export source run sarif --output FILE", ["export", "--db", db("scan-main"), "--run", sourceRunId ?? "missing", "--format", "sarif", "--output", sarifExport], { files: [sarifExport] });
  const vexExport = out("claims.cdx-vex.json");
  await step("export deps run cyclonedx-vex --output FILE", ["export", "--db", db("deps-main"), "--run", depsRunId ?? "missing", "--format", "cyclonedx-vex", "--output", vexExport], { files: [vexExport] });
  await step("import sarif", ["import", "--db", importDb, path.join(W, "vex/report.sarif")]);
  await step("import sarif --json", ["import", "--db", importDb, "--json", path.join(W, "vex/report.sarif")]);
  await step("import openvex --json", ["import", "--db", importDb, "--json", path.join(W, "vex/openvex.json")]);
  await step("import cyclonedx-vex --json", ["import", "--db", importDb, "--json", path.join(W, "vex/cyclonedx-vex.json")]);
  await step("vex claims", ["vex", "claims", "--db", importDb]);
  const claims = json(await step("vex claims --json", ["vex", "claims", "--db", importDb, "--json"]));
  const sha = Array.isArray(claims) ? claims.find((c) => c.contentSha256)?.contentSha256 : claims?.documents?.[0]?.contentSha256;
  await step("vex trust", ["vex", "trust", "--db", importDb, "--sha", sha ?? "missing", "--by", "Parity Reviewer", "--note", "fixture"], { ok: [0, 1, 2, 3] });
  await step("vex claims --json (trusted)", ["vex", "claims", "--db", importDb, "--json"]);
  await step("vex suggest --json", ["vex", "suggest", "--db", importDb, "--run", depsRunId ?? "missing", "--json"], { ok: [0, 1, 2, 3] });
  await step("vex revoke", ["vex", "revoke", "--db", importDb, "--sha", sha ?? "missing"], { ok: [0, 1, 2, 3] });
  // Documents exported from this run carry random ids, so import them last,
  // into their own database, after everything that lists claims.
  await step("import exported cyclonedx-vex --json", ["import", "--db", db("claims-exported"), "--json", vexExport], { ok: [0, 1, 2, 3] });
  await step("import exported sarif --json", ["import", "--db", db("claims-exported"), "--json", sarifExport], { ok: [0, 1, 2, 3] });

  // --- compliance
  await step("compliance profiles", ["compliance", "profiles"]);
  const profiles = json(await step("compliance profiles --json", ["compliance", "profiles", "--json"]));
  const profileId = (Array.isArray(profiles) ? profiles : profiles?.profiles ?? [])[0]?.id ?? "missing";
  const comp = db("compliance");
  await step("deps (seed compliance db)", ["deps", deps, "--offline", "--advisory-db", adv, "--db", comp, "--format", "json"], { ok: [0, 1] });
  const assessJson = await step("compliance assess --json", ["compliance", "assess", "--db", comp, "--profile", profileId, "--organization", "Parity Org", "--assessor", "Parity Assessor", "--json", deps], { ok: [0, 1] });
  const assessed = json(assessJson);
  const assessmentId = (Array.isArray(assessed) ? assessed : assessed?.assessments ?? [assessed])[0]?.id;
  await step("compliance list", ["compliance", "list", "--db", comp]);
  await step("compliance list --json", ["compliance", "list", "--db", comp, "--json"]);
  await step("compliance show", ["compliance", "show", "--db", comp, "--latest"]);
  const shown = json(await step("compliance show --json", ["compliance", "show", "--db", comp, "--latest", "--json"]));
  const controlId = shown?.controls?.[0]?.controlId ?? shown?.controls?.[0]?.id ?? shown?.matrix?.[0]?.controlId ?? "missing";
  await step("compliance review --json", ["compliance", "review", "--db", comp, "--assessment", assessmentId ?? "missing", "--control", controlId, "--status", "partial", "--note", "Reviewed fixture", "--by", "Parity Reviewer", "--json"], { ok: [0, 1, 2] });
  await step("compliance show --json (reviewed)", ["compliance", "show", "--db", comp, "--latest", "--json"]);
  for (const format of ["json", "markdown", "csv", "html", "pdf"]) {
    const file = out(`compliance.${format}`);
    await step(`compliance report --format ${format}`, ["compliance", "report", "--db", comp, "--latest", "--format", format, "-o", file, "--json"], { files: [file], ok: [0, 1, 2] });
  }

  // --- the rest
  await step("languages", ["languages"]);
  await step("benchmark", ["benchmark", "--corpus", path.join(repo, "benchmarks/corpus")], { ok: [0, 1, 2, 3] });
  await step("benchmark --json", ["benchmark", "--corpus", path.join(repo, "benchmarks/corpus"), "--json"], { ok: [0, 1, 2, 3] });
  await step("hook status", ["hook", "status"], { cwd: repoDir, ok: [0, 1, 2, 3] });
  await step("hook install", ["hook", "install"], { cwd: repoDir, ok: [0, 1, 2, 3] });
  await step("hook status (installed)", ["hook", "status"], { cwd: repoDir, ok: [0, 1, 2, 3] });
  await step("hook uninstall", ["hook", "uninstall"], { cwd: repoDir, ok: [0, 1, 2, 3] });
  await step("scan (usage error)", ["scan", path.join(W, "does-not-exist")], { ok: [2, 3] });

  return results;
}

// ---------------------------------------------------------------------------
// Comparison

function unifiedDiff(label, a, b, tmp) {
  const left = path.join(tmp, "left.txt"), right = path.join(tmp, "right.txt");
  return Promise.all([writeFile(left, a), writeFile(right, b)]).then(() => {
    const result = spawnSync("diff", ["-u", "--label", `${label} (ON, preserve_order)`, "--label", `${label} (OFF)`, left, right], { encoding: "utf8" });
    return (result.stdout || "").split("\n").slice(0, 60).join("\n");
  });
}

const NOT_COVERED = [
  ["scan/deps/sca with live advisory or release-fact providers (OSV, CISA KEV, deps.dev)", "need the network; the harness refuses all outbound requests so every run is offline and identical"],
  ["deps --offline replaying a stored OSV receipt", "a receipt is only written after an online OSV query; --advisory-db is exercised instead"],
  ["advisory-db update against OSV itself; rule-pack update --feed; monitor --update/--webhook", "network; update is exercised against a local dump server"],
  ["image with a registry reference", "network"],
  ["external-benchmark", "needs the fetched OWASP Benchmark checkout"],
  ["yara / template / signature-pack commands", "only exist in the yara build; no OFF counterpart (deliberately out of scope)"],
  ["compliance report PDF bytes", "Flate-compressed streams embed random assessment ids, so only the %PDF header is compared (the JSON/Markdown/CSV/HTML renderings of the same report are compared in full)"],
  ["desktop (Tauri) and headless-server IPC responses", "not CLI; the server and command layers are not driven by this script"],
];

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const root = await realpath(await mkdtemp(path.join(tmpdir(), "oxaudit-parity-")));
  const refused = [];
  const proxy = createServer((request, response) => { refused.push(request.url); response.writeHead(502); response.end("refused by parity check\n"); });
  proxy.on("connect", (request, socket) => { refused.push(request.url); socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); });
  const dump = advisoryDump();
  const dumpServer = createServer((request, response) => { response.writeHead(200, { "content-type": "application/zip", "content-length": dump.length }); response.end(dump); });
  const listen = (server) => new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  await Promise.all([listen(proxy), listen(dumpServer)]);
  const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
  const dumpUrl = `http://127.0.0.1:${dumpServer.address().port}`;

  const outcomes = {};
  try {
    // "on2" is the ON binary again: whatever differs between two runs of the same
    // binary cannot be attributed to preserve_order (see weaklyEqual).
    for (const [side, cli] of [["on", options.on], ["on2", options.on], ["off", options.off]]) {
      const resolved = await realpath(cli);
      await access(resolved);
      // The same workspace path for both binaries, wiped in between, so no
      // path needs normalising.
      const W = path.join(root, "work");
      await rm(W, { recursive: true, force: true });
      await mkdir(path.join(W, "db"), { recursive: true }); await mkdir(path.join(W, "out"), { recursive: true });
      await chmod(path.join(W, "db"), 0o700); // the CLI refuses a database directory that others can read
      const env = {
        PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: root, TZ: "UTC", LC_ALL: "C", LANG: "C", NO_COLOR: "1",
        HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, ALL_PROXY: proxyUrl, http_proxy: proxyUrl, https_proxy: proxyUrl, all_proxy: proxyUrl,
        NO_PROXY: "127.0.0.1", no_proxy: "127.0.0.1",
        GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
        GIT_AUTHOR_NAME: "Parity", GIT_AUTHOR_EMAIL: "parity@example.invalid", GIT_COMMITTER_NAME: "Parity", GIT_COMMITTER_EMAIL: "parity@example.invalid",
        GIT_AUTHOR_DATE: "2024-01-01T00:00:00Z", GIT_COMMITTER_DATE: "2024-01-01T00:00:00Z",
      };
      await materialise(W, env);
      const started = Date.now();
      const results = await scenario({ cli: resolved, W, env, dumpUrl, filter: options.only });
      outcomes[side] = results;
      if (options.dump) {
        // Raw (un-normalised) outputs, for diagnosing a failure by hand.
        const base = path.join(path.resolve(options.dump), side);
        await mkdir(base, { recursive: true });
        for (const [position, record] of results.entries()) {
          if (record.skipped) continue;
          const stem = `${String(position).padStart(3, "0")}-${record.label.replace(/[^A-Za-z0-9.-]+/g, "_")}`;
          await writeFile(path.join(base, `${stem}.stdout`), record.stdout);
          await writeFile(path.join(base, `${stem}.stderr`), record.stderr);
          for (const [name, content] of Object.entries(record.files)) await writeFile(path.join(base, `${stem}.file-${path.basename(name)}`), content);
        }
      }
      console.log(`${side.toUpperCase()}: ${results.length} commands in ${((Date.now() - started) / 1000).toFixed(1)}s (${resolved})`);
      if (options.keep) { console.log(`  workspace kept at ${W}`); }
    }

    const allText = (side) => outcomes[side].filter((r) => !r.skipped).flatMap((r) => [r.stdout, r.stderr, ...Object.values(r.files)].map((b) => Buffer.from(b).toString("latin1")));
    const volatile = volatileContexts(allText("on"), allText("on2"));
    if (options.verbose) console.log(`volatile digest contexts: ${[...volatile].join(", ") || "(none)"}`);
    const strict = { on: makeNormaliser(true, volatile), on2: makeNormaliser(true, volatile), off: makeNormaliser(true, volatile) };
    const flat = makeNormaliser(false, volatile);
    const diffDir = path.join(root, "diff"); await mkdir(diffDir, { recursive: true });
    const failures = [], unexpected = [], covered = [], unstable = [];
    const total = outcomes.on.length;
    if (outcomes.off.length !== total || outcomes.on2.length !== total) throw new Error("scenarios diverged in length");
    for (let index = 0; index < total; index += 1) {
      const a = outcomes.on[index], c = outcomes.on2[index], b = outcomes.off[index];
      if (a.skipped) continue;
      if (a.label !== b.label || a.label !== c.label) throw new Error(`scenario order diverged at ${a.label} / ${b.label}`);
      const names = ["exit code", "stdout", "stderr", ...Object.keys(a.files).map((name) => `file ${name}`)];
      const pick = (record, name) => name === "exit code" ? `${record.code}\n` : name === "stdout" ? record.stdout : name === "stderr" ? record.stderr : (record.files[name.slice(5)] ?? Buffer.from("<missing>"));
      let first = null;
      for (const name of names) {
        if (name === "exit code") {
          if (a.code !== b.code && !first) first = { name, l: pick(a, name), r: pick(b, name) };
          continue;
        }
        // Normalise in a fixed order (stdout, stderr, files) so id numbering is comparable.
        if (name.endsWith(".pdf")) {
          // Compressed streams embed random ids; compare only that both are PDFs.
          if (pick(a, name).subarray(0, 5).toString() !== pick(b, name).subarray(0, 5).toString() && !first) first = { name, l: "%PDF header\n", r: "no %PDF header\n" };
          continue;
        }
        const text = (record, side) => strict[side](Buffer.from(pick(record, name)).toString("latin1"));
        const l = text(a, "on"), l2 = text(c, "on2"), r = text(b, "off");
        if (l === l2) {
          if (l !== r && !first) first = { name, l, r };
        } else {
          const result = weaklyEqual(flat(Buffer.from(pick(a, name)).toString("latin1")), flat(Buffer.from(pick(b, name)).toString("latin1")));
          unstable.push(`${a.label}: ${name}${result.equal ? "" : ` (DIFFERS in ${result.why})`}`);
          if (!result.equal && !first) first = { name: `${name} [run-to-run unstable; compared by ${result.why}]`, l: result.left, r: result.right };
        }
      }
      if (first) failures.push({ label: a.label, name: first.name, diff: await unifiedDiff(`${a.label}: ${first.name}`, first.l, first.r, diffDir) });
      if (!a.expected || !b.expected) unexpected.push(`${a.label} (exit ON ${a.code}, OFF ${b.code})${options.verbose ? `: ${a.stderr.toString().trim().split("\n").slice(-2).join(" | ").slice(0, 300)}` : ""}`);
      covered.push({ label: a.label, code: a.code, bytes: a.stdout.length + Object.values(a.files).reduce((n, f) => n + f.length, 0) });
    }
    if (unstable.length) {
      console.log(`\n${unstable.length} output(s) differ between two runs of the SAME binary (list order follows random ids); byte equality is impossible there, so they were compared by line multiset and per-object key order instead:`);
      for (const line of unstable) console.log(`  ${line}`);
    }

    console.log(`\nCompared ${covered.length} commands (stdout, stderr, exit code and written files; ${covered.reduce((n, c) => n + c.bytes, 0)} bytes of report output).`);
    if (options.verbose) for (const c of covered) console.log(`  exit ${c.code}  ${String(c.bytes).padStart(8)} B  ${c.label}`);
    if (unexpected.length) {
      console.log("\nCommands whose exit code was outside the scenario's expectation (compared anyway, but they may not exercise the output path):");
      for (const line of unexpected) console.log(`  ${line}`);
    }
    console.log("\nNot covered:");
    for (const [what, why] of NOT_COVERED) console.log(`  - ${what}: ${why}`);
    if (refused.length) console.log(`\n(${refused.length} outbound request(s) were refused by the harness proxy.)`);

    if (failures.length) {
      console.log(`\nFAIL: ${failures.length} command(s) differ between the preserve_order build and the sorted build.\n`);
      for (const failure of failures) console.log(`### ${failure.label}: first difference in ${failure.name}\n${failure.diff}\n`);
      process.exitCode = 1;
    } else {
      console.log("\nPASS: both builds produced identical output for every compared command.");
    }
  } finally {
    await new Promise((resolve) => proxy.close(resolve));
    await new Promise((resolve) => dumpServer.close(resolve));
    if (!options.keep) await rm(root, { recursive: true, force: true });
    else console.log(`kept ${root}`);
  }
}

main().catch((error) => { console.error(`check-json-order-parity: ${error.message}`); process.exitCode = 2; });
