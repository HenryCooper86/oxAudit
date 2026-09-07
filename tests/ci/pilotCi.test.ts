import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
const exec = promisify(execFile);
const workflow = await readFile(new URL("../../examples/ci/oxaudit.yml", import.meta.url), "utf8");
function shellFor(name: string) {
  const section = workflow.split(`      - name: ${name}\n`)[1]?.split("\n      - name:")[0];
  assert.ok(section, `Missing executable workflow step: ${name}`);
  const script = section.split("        run: |\n")[1];
  assert.ok(script, `Missing shell body: ${name}`);
  return script.split("\n").filter((line) => line.startsWith("          ")).map((line) => line.slice(10)).join("\n") + "\n";
}
const scanShell = shellFor("Scan target once and export the same completed run");
const provenanceShell = shellFor("Validate main baseline provenance");
const gateShell = shellFor("Enforce scan completion and findings gate");
async function setup() {
  const root = await mkdtemp(path.join(tmpdir(), "oxaudit CI shell "));
  const directory = path.join(root, "tool/src-tauri/target/debug");
  await mkdir(directory, { recursive: true }); await mkdir(path.join(root, "target"));
  const output = path.join(root, "outputs"); await writeFile(output, "");
  const cli = path.join(directory, "oxaudit-cli");
  const env = { ...process.env, GITHUB_WORKSPACE: root, GITHUB_OUTPUT: output,
    GITHUB_RUN_ID: "123", TARGET_SHA: "target", OXAUDIT_TOOL_COMMIT: "trusted-tool", SCAN_EVENT: "push" };
  return { root, cli, output, env };
}
const fakeCli = `#!${process.execPath}
import fs from 'node:fs';
const args=process.argv.slice(2),arg=(flag)=>args[args.indexOf(flag)+1];
if(args[0]==='scan') {fs.writeFileSync(arg('--output'), JSON.stringify({summary:{filesScanned:1}, findings:[{ruleId:'js-eval'}]}));process.exitCode=Number(process.env.SCAN_FAULT_EXIT||0);}
else if(args[0]==='runs')console.log(JSON.stringify([{id:'canonical-123',kind:'source',state:process.env.SCAN_FAULT_STATE||'completed'}]));
else if(args[0]==='export'){if(arg('--run')!=='canonical-123')throw Error('Wrong run exported');fs.writeFileSync(arg('--output'),JSON.stringify({version:'2.1.0',runs:[{results:[{ruleId:'js-eval'}]}]}));}
else throw Error('Unexpected CLI command');
`;
async function shell(script: string, root: string, env: NodeJS.ProcessEnv) {
  return exec("bash", ["-euo", "pipefail", "-c", script], { cwd: root, env });
}
for (const exit of [0, 1]) test(`consumer scan exits ${exit}: exports completed evidence before enforcing the gate`, async () => {
  const ctx = await setup();
  try {
    await writeFile(ctx.cli, fakeCli); await chmod(ctx.cli, 0o755);
    await shell(scanShell, ctx.root, { ...ctx.env, SCAN_FAULT_EXIT: String(exit) });
    assert.match(await readFile(ctx.output, "utf8"), /completed=true/);
    const provenance=JSON.parse(await readFile(path.join(ctx.root, "reports/provenance.json"), "utf8"));
    assert.equal(provenance.sourceRunId, "canonical-123");
    assert.equal(provenance.targetCommit, "target");
    assert.equal(provenance.workflowRunId, "123");
    const gate=shell(gateShell,ctx.root,{ ...ctx.env, COMPLETED:"true", SCAN_EXIT:String(exit) });
    if(exit===0) await gate; else await assert.rejects(gate);
    assert.ok(JSON.parse(await readFile(path.join(ctx.root,"reports/source.sarif"),"utf8")).runs.length);
  } finally { await rm(ctx.root,{recursive:true,force:true}); }
});
for (const fault of ["missing-cli", "missing-baseline", "failed-run", "incomplete-exit"]) test(`consumer cannot pass ${fault}`, async () => {
  const ctx=await setup();
  try {
    if(fault!=="missing-cli") {await writeFile(ctx.cli,fakeCli);await chmod(ctx.cli,0o755);}
    await assert.rejects(shell(scanShell,ctx.root,{...ctx.env,
      SCAN_EVENT:fault==="missing-baseline"?"pull_request":"push",
      SCAN_FAULT_STATE:fault==="failed-run"?"failed":"completed",
      SCAN_FAULT_EXIT:fault==="incomplete-exit"?"3":"0"}));
    assert.doesNotMatch(await readFile(ctx.output,"utf8"),/completed=true/);
    await assert.rejects(shell(gateShell,ctx.root,{...ctx.env,COMPLETED:"",SCAN_EXIT:""}));
  } finally {await rm(ctx.root,{recursive:true,force:true});}
});
test("consumer baseline provenance rejects another commit, tool, run, or incomplete source", async () => {
  const ctx=await setup();
  try {
    const dir=path.join(ctx.root,"baseline-input");await mkdir(dir);await writeFile(path.join(dir,"baseline.json"),'{"findings":[]}');
    const provenance={schemaVersion:1,toolCommit:"trusted-tool",targetCommit:"main-sha",workflowRunId:"456",sourceRunState:"completed"};
    const env={...ctx.env,BASE_SHA:"main-sha",BASELINE_RUN_ID:"456"};
    await writeFile(path.join(dir,"provenance.json"),JSON.stringify(provenance));await shell(provenanceShell,ctx.root,env);
    for(const change of [{targetCommit:"pr-sha"},{toolCommit:"untrusted-tool"},{workflowRunId:"789"},{sourceRunState:"failed"}]) {
      await writeFile(path.join(dir,"provenance.json"),JSON.stringify({...provenance,...change}));
      await assert.rejects(shell(provenanceShell,ctx.root,env));
    }
  } finally {await rm(ctx.root,{recursive:true,force:true});}
});
// Optional local integration: the same workflow shell against a freshly built
// CLI. The caller supplies child-only refusing proxy variables (see task report).
test("consumer workflow shell against supplied real CLI", {skip: !process.env.PILOT_REAL_CLI}, async () => {
  const ctx=await setup();
  try {
    await symlink(path.resolve(process.env.PILOT_REAL_CLI!),ctx.cli);
    await writeFile(path.join(ctx.root,"target/handler.js"),'export function parsePayload(input) { return eval(input); }\n');
    await shell(scanShell,ctx.root,ctx.env);
    assert.match(await readFile(ctx.output,"utf8"),/completed=true/);
    const findings=JSON.parse(await readFile(path.join(ctx.root,"reports/source.json"),"utf8")).findings;
    assert.ok(findings.some((finding:{ruleId:string})=>finding.ruleId==="js-eval"));
    await shell(gateShell,ctx.root,{...ctx.env,COMPLETED:"true",SCAN_EXIT:"0"});
  } finally {await rm(ctx.root,{recursive:true,force:true});}
});
