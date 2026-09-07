import { describe, expect, it } from 'vitest';
import type { Vulnerability, DependencyPath } from '../../lib/types';
import { affectedBy, upgradeGroups } from './decisions';
const path = (workspace = '', transitive = false): DependencyPath => ({workspace,entryPoint:transitive?'parent':'leaf',chain:[...(transitive?[{name:'parent',packageName:'parent',installPath:'node_modules/parent',dependencyType:'runtime',declared:'^1.0.0'}]:[]),{name:'leaf',packageName:'leaf',installPath:'node_modules/leaf',dependencyType:'runtime',declared:'^1.0.0'}]});
const vuln = (events: Array<Record<string,string>>, changes: Partial<Vulnerability> = {}): Vulnerability => ({id:'A',aliases:[],summary:'original summary',details:'original detail',severity:'high',cvssScore:8,epss:null,epssPercentile:null,knownExploited:false,ransomware:false,publicExploit:false,directUsage:{referenced:null,referencedFiles:0,exampleFile:null},ecosystem:'npm',packageName:'leaf',installedVersion:'1.0.0',fixedVersions:['9.9.9'],affectedRange:'legacy lossy string',references:[],published:null,modified:null,lockfile:'/repo/package-lock.json',occurrence:{installPath:'node_modules/leaf',status:'available',paths:[path()],warnings:[]},affectedEvidence:{ecosystem:'npm',packageName:'leaf',records:[{package:{ecosystem:'npm',name:'leaf'},ranges:[{type:'SEMVER',events}]}]},...changes});
const fixed: Array<Record<string,string>> = [{introduced:'0'}, {fixed:'1.0.1'}];
describe('supported advisory range evidence', () => {
  it('evaluates disjoint intervals, ordered events, inclusive last_affected and exclusive limit', () => {
    const v=vuln([{fixed:'2.0.1'},{introduced:'0'},{fixed:'1.0.1'},{introduced:'2.0.0'}]);
    expect(affectedBy(v,'1.0.1')).toBe(false);
    expect(affectedBy(v,'2.0.0')).toBe(true);
    expect(affectedBy(v,'2.0.1')).toBe(false);
    expect(affectedBy(vuln([{introduced:'0'},{last_affected:'1.0.1'}]),'1.0.1')).toBe(true);
    expect(affectedBy(vuln([{introduced:'0'},{last_affected:'1.0.1'}]),'1.0.2')).toBe(false);
    expect(affectedBy(vuln([{introduced:'0'},{limit:'1.0.1'}]),'1.0.1')).toBe(false);
    expect(affectedBy(vuln([{introduced:'0'},{limit:'1.0.1'},{limit:'2.0.0'}]),'1.5.0')).toBe(true);
  });
  it('requires all ranges and enumerated versions, matching identity, and supported semantics',()=>{
    const v=vuln(fixed); v.affectedEvidence!.records[0].versions=['1.0.1'];
    expect(affectedBy(v,'1.0.1')).toBe(true);
    v.affectedEvidence!.records[0].ranges!.push({type:'GIT',events:fixed});
    expect(affectedBy(v,'1.0.2')).toBeNull();
    expect(affectedBy(vuln(fixed,{affectedEvidence:null}),'1.0.1')).toBeNull();
    expect(affectedBy(vuln([{introduced:'0'},{fixed:'1.0.1-beta'}]),'1.0.1')).toBeNull();
    expect(affectedBy(vuln(fixed,{packageName:'other'}),'1.0.1')).toBeNull();
    expect(affectedBy(vuln([{fixed:'1.0.1'}]),'1.0.1')).toBeNull();
  });
});
describe('occurrence and entrypoint decisions',()=>{
  it('chooses the smallest supplied fix clearing every advisory and classifies the version change',()=>{
    const groups=upgradeGroups([vuln(fixed),vuln([{introduced:'0'},{fixed:'1.1.0'}],{id:'B'})]);
    expect(groups).toHaveLength(1);expect(groups[0].advisories).toHaveLength(2);
    expect(groups[0].candidate).toBe('1.1.0');expect(groups[0].classification).toBe('minor');
    expect(groups[0].command).toBe("npm install --ignore-scripts --save-prod -- 'leaf@1.1.0'");
    expect(upgradeGroups([vuln(fixed)])[0].classification).toBe('patch');
    expect(upgradeGroups([vuln([{introduced:'0'},{fixed:'2.0.0'}])])[0].classification).toBe('major');
  });
  it('preserves same version occurrences, workspaces and lockfiles; transitive and alias updates use checklists',()=>{
    const root=vuln(fixed);
    const nested=vuln(fixed,{occurrence:{installPath:'node_modules/parent/node_modules/leaf',status:'available',paths:[path('',true)],warnings:[]}});
    const workspace=vuln(fixed,{occurrence:{...root.occurrence!,paths:[path('packages/worker')]}});
    const other=vuln(fixed,{lockfile:'/repo/other/package-lock.json'});
    const groups=upgradeGroups([root,nested,workspace,other]);
    expect(groups).toHaveLength(4);
    expect(groups.find(g=>g.paths[0]?.entryPoint==='parent')?.command).toBeNull();
    expect(groups.find(g=>g.paths[0]?.entryPoint==='parent')?.checklist).toContain('parent');
    expect(groups.find(g=>g.paths[0]?.workspace==='packages/worker')?.command).toContain("--workspace 'packages/worker'");
    const alias=vuln(fixed);alias.occurrence!.paths[0].chain[0].name='alias';
    expect(upgradeGroups([alias])[0].command).toBeNull();
  });
  it('keeps historical, unknown, unresolved and conflicting evidence manual',()=>{
    for(const v of [vuln(fixed,{occurrence:undefined,affectedEvidence:null}),vuln([{introduced:'0'}]),vuln([{introduced:'0'},{last_affected:'1.0.1'}])]) {
      const group=upgradeGroups([v])[0];expect(group.candidate).toBeNull();expect(group.command).toBeNull();expect(group.checklist).toContain('Recheck');
    }
    const v=vuln(fixed);v.occurrence!.paths=[];expect(upgradeGroups([v])[0].command).toBeNull();
  });
});
it('never replaces a local workspace link with a registry command or upgrades inconsistent affected evidence',()=>{
  const local=vuln(fixed);local.occurrence!.localWorkspace=true;
  expect(upgradeGroups([local])[0].command).toBeNull();
  expect(upgradeGroups([vuln([{introduced:'2.0.0'},{fixed:'2.0.1'}])])[0].candidate).toBeNull();
});
it('malformed raw ranges are unknown instead of crashing the decision view',()=>{
  const malformed=vuln(fixed);
  malformed.affectedEvidence!.records[0].ranges=[null] as unknown as NonNullable<typeof malformed.affectedEvidence>['records'][0]['ranges'];
  expect(affectedBy(malformed,'1.0.1')).toBeNull();
  expect(upgradeGroups([malformed])[0].candidate).toBeNull();
});
