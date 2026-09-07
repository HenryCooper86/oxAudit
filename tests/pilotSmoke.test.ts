import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

// Exercise real process spawning/report validation/cleanup; only the external
// CLI is replaced. Its fault switches represent CLI regressions, not providers.
const fake = `
import fs from 'node:fs';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
const args=process.argv.slice(2), command=args[0];
const value=(flag)=>args[args.indexOf(flag)+1];
const db=value('--db');
const fault=process.env.PILOT_TEST_FAULT;
let rows=fs.existsSync(db)?JSON.parse(fs.readFileSync(db,'utf8')):[];
const output=(data)=>{ if(fault==='missing-report') return; const out=value('--output'); if(args.includes('--output')) fs.writeFileSync(out,JSON.stringify(data));else console.log(JSON.stringify(data)); };
if(command==='scan'){
  const vulnerable=fs.readFileSync(args[1]+'/handler.js','utf8').includes('eval(input)');
  if(vulnerable && fault!=='proxy-bypass'){
    if(process.env.NO_PROXY!=='' || process.env.no_proxy!=='' || !process.env.https_proxy.startsWith('http://127.0.0.1:')) throw Error('proxy configuration lost');
    const proxy=new URL(process.env.HTTPS_PROXY);
    await new Promise((resolve,reject)=>{const req=http.request({hostname:proxy.hostname,port:proxy.port,method:'CONNECT',path:'www.cisa.gov:443'}); req.on('connect',(res,socket)=>{socket.destroy(); res.statusCode===502?resolve():reject(Error('unexpected proxy response'));});req.on('error',reject);req.end();});
  }
  const findings=vulnerable?[{ruleId:'js-eval',severity:'high',fingerprint:'pilot-id'}]:[];
  const report={summary:{filesScanned:1,filesSkipped:0,totalFindings:findings.length},findings};
  const id=randomUUID();
  rows.unshift({id,kind:'source',state:fault==='incomplete'?'failed':'completed',targetLabel:'project'});fs.writeFileSync(db,JSON.stringify(rows));
  output(report);
  if(args.includes('--baseline')){
    const previous=JSON.parse(fs.readFileSync(value('--baseline'),'utf8'));
    if(!vulnerable && previous.findings.length) console.error('1 no longer observed (coverage unverified)');
    if(vulnerable && previous.findings.length===0 && fault!=='gate-ignored') process.exitCode=1;
  }else if(args.includes('--fail-on')&&vulnerable)process.exitCode=1;
}else if(command==='runs')output(rows.slice(0,Number(value('--limit'))));
else if(command==='export')output({version:'2.1.0',runs:[{results:fault==='empty-sarif'?[]:[{ruleId:'js-eval'}]}]});
else if(command==='deps'){console.error('invalid lockfile');process.exitCode=fault==='malformed-ignored'?0:3;}
else throw Error('unknown command');
`;
async function exercise(fault?: string) {
  const owned = await mkdtemp(path.join(tmpdir(), "oxaudit pilot test "));
  try {
    const cli = path.join(owned, "fake cli.mjs"); await writeFile(cli, fake);
    const { runPilot } = await import("../tools/pilot-smoke.mjs");
    return await runPilot({ cli: process.execPath, cliArgs: [cli], tempParent: owned,
      env: { ...process.env, PILOT_TEST_FAULT: fault ?? "" } });
  } finally { await rm(owned, { recursive: true, force: true }); }
}
test("pilot validates source gate, report evidence and durable history, then removes only its owned workspace", async () => {
  const before = { ...process.env };
  const result = await exercise();
  assert.equal(result.status, "passed");
  assert.equal(result.correctedEvidence, "no longer observed (coverage unverified)");
  assert.ok(result.refusedRequests.some((request: { target: string }) => request.target === "www.cisa.gov:443"));
  assert.equal(result.sourceRunIds.length, 4);
  assert.ok(Object.keys(process.env).length === Object.keys(before).length && Object.entries(before).every(([key, value]) => process.env[key] === value), "pilot changed the parent environment");
  await assert.rejects(access(result.temporaryDirectory));
});
for (const [fault, message] of [
  ["gate-ignored", /introduced.*exit 1/i],
  ["malformed-ignored", /malformed.*exit 3/i],
  ["incomplete", /completed source run/i],
  ["missing-report", /ENOENT/],
  ["empty-sarif", /SARIF.*js-eval/i],
  ["proxy-bypass", /refusing proxy/i],
]) test(`pilot fails on ${fault}`, async () => { await assert.rejects(exercise(fault), message); });
test("pilot refuses missing CLI and does not remove unrelated files", async () => {
  const owned=await mkdtemp(path.join(tmpdir(),"oxaudit-pilot-neighbor-"));
  try {
    await writeFile(path.join(owned,"keep.txt"),"keep");
    const { runPilot }=await import("../tools/pilot-smoke.mjs");
    await assert.rejects(runPilot({cli:path.join(owned,"missing"),tempParent:owned}),/ENOENT/);
    assert.equal(await readFile(path.join(owned,"keep.txt"),"utf8"),"keep");
  } finally { await rm(owned,{recursive:true,force:true}); }
});
