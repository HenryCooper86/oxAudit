import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

test("RSS parsing preserves macOS bytes, Linux KiB and explicit unknown capabilities", async () => {
  const { parsePeakRss } = await import("../tools/cli-performance.mjs");
  assert.equal(parsePeakRss("   33554432  maximum resident set size", "darwin").peakRssBytes, 33554432);
  assert.equal(parsePeakRss(" Maximum resident set size (kbytes): 32768", "linux").peakRssBytes, 33554432);
  assert.equal(parsePeakRss("", "win32").peakRssBytes, null);
  assert.match(parsePeakRss("", "linux").reason, /missing/);
});
test("measurement runs a real child and records elapsed time independently of its reported work", async () => {
  const { measureCommand } = await import("../tools/cli-performance.mjs");
  const result = await measureCommand({ command: process.execPath, args: ["-e", "setTimeout(()=>console.log('done'),40)"], cwd: tmpdir(), env: process.env });
  assert.equal(result.exit, 0);
  assert.match(result.stdout, /done/);
  assert.ok(result.elapsedMs >= 40);
  assert.ok(result.memory.peakRssBytes === null || result.memory.peakRssBytes > 5 * 1024 * 1024);
});
test("measurement fails a stalled child without leaving the work pending", async () => {
  const { measureCommand } = await import("../tools/cli-performance.mjs");
  await assert.rejects(measureCommand({ command: process.execPath, args: ["-e", "setTimeout(()=>{},10000)"], cwd: tmpdir(), env: process.env, timeoutMs: 40 }), /timed out/);
});
const fakeCli = String.raw`
import fs from 'node:fs'; import http from 'node:http';
const args=process.argv.slice(2), command=args[0], get=(flag)=>args[args.indexOf(flag)+1];
const fail=process.env.PERFORMANCE_TEST_FAULT;
if(command==='--version') console.log('oxaudit-cli test');
else if(command==='runs') console.log('[]');
else if(command==='scan') {
  const files=fs.readdirSync(args[1]).filter(f=>f.endsWith('.js'));
  const findings=files.flatMap(file=>fs.readFileSync(args[1]+'/'+file,'utf8').split('\n').filter(line=>line.includes('eval(input)')).map(()=>({ruleId:'js-eval',filePath:fail==='finding-identity'?files[0]:file})));
  const proxy=new URL(process.env.HTTPS_PROXY);
  await new Promise((resolve,reject)=>{const req=http.request({hostname:proxy.hostname,port:proxy.port,path:'www.cisa.gov:443',method:'CONNECT'});req.on('connect',(res,socket)=>{socket.destroy();res.statusCode===502?resolve():reject(Error('proxy forwarded'));});req.on('error',reject);req.end();});
  fs.writeFileSync(get('--output'),JSON.stringify({summary:{filesScanned:fail==='coverage'?0:files.length,filesSkipped:0,totalFindings:findings.length},findings}));
} else if(command==='image') {
  const content=fs.readFileSync(args[1]); if(!content.includes(Buffer.from('ustar')))throw Error('not tar');
  const components=Array.from({length:1000},(_,i)=>({product:'fixture-'+(fail==='native-identity'?0:i),version:'1.0.0',paths:['fixture']}));
  fs.writeFileSync(get('--output'),JSON.stringify({components,summary:{components:components.length,vulnerabilities:0}}));
} else if(command==='deps') {
  if(!args.includes('--offline'))throw Error('offline required');
  const lock=JSON.parse(fs.readFileSync(args[1]+'/package-lock.json','utf8'));
  const dependencies=Object.entries(lock.packages).filter(([key])=>key.startsWith('node_modules/')).map(([key,p])=>({name:fail==='dependency-identity'?'fixture-0':key.slice(13),version:p.version,ecosystem:'npm'}));
  fs.writeFileSync(get('--output'),JSON.stringify({summary:{packagesFound:dependencies.length,packagesQueried:dependencies.length,advisoryCoverage:fail==='receipt'?'unknown':'complete',advisorySource:'osv-cache'},dependencies,vulnerabilities:[]}));
} else throw Error('unknown command');
`;
async function exercise(fault = "") {
  const owned = await mkdtemp(path.join(tmpdir(), "oxaudit-perf-test-"));
  try {
    const fixture = path.join(owned, "cli fixture.mjs"); await writeFile(fixture, fakeCli);
    const { runPerformance } = await import("../tools/cli-performance.mjs");
    return await runPerformance({ cli: process.execPath, cliArgs: [fixture], tempParent: owned, env: { ...process.env, PERFORMANCE_TEST_FAULT: fault } });
  } finally { await rm(owned, { recursive: true, force: true }); }
}
test("owned workloads keep source, nested archive, saved image and synthetic dependency cache populations explicit", async () => {
  const envBefore = { ...process.env };
  const result = await exercise();
  assert.equal(result.status, "passed");
  assert.deepEqual(result.workloads.map((row: any) => row.id), ["source-findings", "nested-archive", "saved-image", "dependency-cache"]);
  assert.equal(result.workloads[0].population.sourceFiles, 128);
  assert.equal(result.workloads[0].observed.findings, 2048);
  assert.equal(result.workloads[3].population.packageQueries, 2000);
  assert.equal(result.workloads[3].advisoryEvidence, "synthetic empty test receipt; no provider accuracy claim");
  assert.ok(result.refusedRequests.some((request: any) => request.target === "www.cisa.gov:443"));
  assert.ok(Object.keys(process.env).length === Object.keys(envBefore).length && Object.entries(envBefore).every(([key, value]) => process.env[key] === value), "performance changed the parent environment");
  await assert.rejects(access(result.temporaryDirectory));
});
for (const [fault, error] of [["coverage", /source coverage/], ["receipt", /advisory coverage/], ["finding-identity", /source finding identities/], ["native-identity", /native fixture identities/], ["dependency-identity", /dependency fixture identities/]] as const) test(`performance rejects ${fault} rather than publishing incomplete population evidence`, async () => {
  await assert.rejects(exercise(fault), error);
});
