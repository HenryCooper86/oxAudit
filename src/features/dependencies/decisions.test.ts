import { describe, expect, it } from 'vitest';
import type { Vulnerability, DependencyPath } from '../../lib/types';
import { affectedBy, compareVersions, upgradeGroups, versionFamilyFor, versionFamilyForEcosystem, type VersionFamily, type VersionOrdering } from './decisions';
import sharedVectors from '../../../src-tauri/tests/fixtures/version-ordering-vectors.json';
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
    expect(affectedBy(vuln([{introduced:'0'},{fixed:'1.0.1-beta'}]),'1.0.1')).toBe(false);
    expect(affectedBy(vuln([{introduced:'0'},{fixed:'not.a.version'}]),'1.0.1')).toBeNull();
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

describe('ecosystem version comparators (ported from advisories/versioning.rs)',()=>{
  const table=(family:VersionFamily,pairs:Array<[string,string,VersionOrdering]>)=>{
    for (const [a,b,expected] of pairs) {
      expect(compareVersions(family,a,b)).toBe(expected);
      expect(compareVersions(family,b,a)).toBe(expected===0?0:expected===1?-1:1);
    }
  };
  it('semver follows semver.org with lockfile leniency',()=>{
    table('semver',[
      ['1.0.0','2.0.0',-1],['2.1.0','2.0.9',1],
      ['1.0.0-alpha','1.0.0',-1],['1.0.0-alpha','1.0.0-alpha.1',-1],
      ['1.0.0-alpha.1','1.0.0-alpha.beta',-1],['1.0.0-alpha.beta','1.0.0-beta',-1],
      ['1.0.0-beta','1.0.0-beta.2',-1],['1.0.0-beta.2','1.0.0-beta.11',-1],
      ['1.0.0-beta.11','1.0.0-rc.1',-1],['1.0.0-rc.1','1.0.0',-1],
      ['1.0.0-1','1.0.0-alpha',-1],
      ['v1.2.3','1.2.3',0],['1.2','1.2.0',0],['1.2.3+build.5','1.2.3',0],
      ['v0.0.0-20180518173023-abc','v0.0.0-20190101111111-abc',-1],
    ]);
    for (const bad of ['','x.y.z','1.2.3.4','1..3']) expect(compareVersions('semver',bad,'1.0.0')).toBeNull();
  });
  it('pep440 orders dev < pre < release < post with epochs and locals',()=>{
    table('pep440',[
      ['1.0','1.0.0',0],['1.0.1','1.0',1],['1.9','1.10',-1],
      ['1!1.0','2.0',1],
      ['1.0.dev1','1.0a1',-1],['1.0a1','1.0a2',-1],['1.0a2','1.0b1',-1],
      ['1.0b1','1.0rc1',-1],['1.0rc1','1.0',-1],['1.0','1.0.post1',-1],
      ['1.0.post1','1.1.dev1',-1],
      ['1.0alpha1','1.0a1',0],['1.0-beta2','1.0b2',0],['1.0-preview3','1.0rc3',0],
      ['1.0rev4','1.0.post4',0],['v1.2.3','1.2.3',0],
      ['1.0','1.0+local',-1],['1.0+local.1','1.0+local.2',-1],
    ]);
    for (const bad of ['','abc','1.0.x','1.0!bad']) expect(compareVersions('pep440',bad,'1.0.0')).toBeNull();
  });
  it('maven follows ComparableVersion: ranked qualifiers, padding and null trimming',()=>{
    table('maven',[
      ['1.0','1.0.1',-1],['1.0','2.0',-1],
      ['1.0-alpha1','1.0-beta1',-1],['1.0-beta1','1.0-milestone1',-1],
      ['1.0-milestone1','1.0-rc1',-1],['1.0-rc1','1.0-SNAPSHOT',-1],
      ['1.0-SNAPSHOT','1.0',-1],['1.0','1.0-sp1',-1],
      ['1.0','1.0.0.1',-1],['1.0.0-alpha','1.0',-1],['1.0.0.0','1.0',0],
      ['1.0-Alpha-1','1.0-alpha-1',0],['1.0-alpha-2','1.0-alpha-10',-1],
      ['5.3.18.RELEASE','5.3.18',0],['1.0-cr1','1.0-rc1',0],['1-a1','1-alpha-1',0],
    ]);
    for (const bad of ['','   ','1.0 beta','1.0-\u00e9']) expect(compareVersions('maven',bad,'1.0.0')).toBeNull();
  });
  it('maven orders unknown qualifiers after every known one, lexically, instead of refusing them',()=>{
    table('maven',[
      ['32.1.3-jre','32.1.3-android',1],['31.1-jre','32.0.0-android',-1],['32.1.3-jre','32.1.3-JRE',0],
      ['1.0-sp1','1.0-jre',-1],['1.0','1.0-jre',-1],['1.0-jre','1.0.1',-1],['1.0-jre','1.0-1',-1],
      ['1.0-LATEST','1.0-omega',-1],['1.0-omega','1.0.0',1],
      ['9.4.43','9.4.43.v20210629',-1],['9.4.43.v20210629','9.4.43.v20210630',-1],['9.4.43.v20210629','9.4.44',-1],
      // Digit strings compare numerically at any width.
      ['1.99999999999999999999999','1.100000000000000000000000',-1],
    ]);
  });
  it('pub orders build metadata after the release, like pub_semver',()=>{
    table('pub',[
      ['1.0.0-pre','1.0.0-pre+build',-1],['1.0.0-pre+build','1.0.0',-1],['1.0.0','1.0.0+build',-1],
      ['1.0.0+2','1.0.0+10',-1],['1.0.0+1','1.0.0+build',-1],['1.0.0+build','1.0.1',-1],['1.0.0+build','1.0.0+build',0],
    ]);
    for (const bad of ['','1.0.0+','1.0.0+a..b','1.0.0+a_b']) expect(compareVersions('pub',bad,'1.0.0')).toBeNull();
    // Plain SemVer still ignores build metadata.
    expect(compareVersions('semver','1.0.0','1.0.0+build')).toBe(0);
  });
  it('gem sorts prerelease segments below numbers',()=>{
    table('gem',[
      ['1.0','1.0.0',0],['1.0.1','1.0',1],['1.9','1.10',-1],
      ['1.0.0.rc1','1.0.0',-1],['1.0.a','1.0.0',-1],['1.0.a','1.0.1',-1],
      ['1.0.rc1','1.0.rc2',-1],['1.0.rc2','1.0.pre',1],
      ['1.0.a','1.0.a.1',-1],['1.0.0.beta.1','1.0.0.beta.2',-1],['v2.1.0','2.1.0',0],
    ]);
    for (const bad of ['','1.0-beta.1','dev-main']) expect(compareVersions('gem',bad,'1.0.0')).toBeNull();
  });
  it('loose handles NuGet four-segment and Composer prerelease pins',()=>{
    table('loose',[
      ['1.0.0','1.0.0.1',-1],['1.0.0.1','1.0.1',-1],['1.0.0.1','1.0.0.2',-1],
      ['1.0.0-beta.1','1.0.0',-1],['1.0.0-beta.1','1.0.0-beta.2',-1],['1.0.0-beta.2','1.0.0-rc',-1],
      ['1.0','1.0.0',0],['v1.2.3','1.2.3',0],['1.2.3+build','1.2.3',0],
    ]);
    for (const bad of ['','dev-main','1.0.x']) expect(compareVersions('loose',bad,'1.0.0')).toBeNull();
  });
  it('rpm follows rpmvercmp over epoch, version and release',()=>{
    table('rpm',[
      ['1.0','2.0',-1],['2.0.1a','2.0.1',1],['5.5p1','5.5p10',-1],['xyz.4','8',-1],['6.0.rc1','6.0',1],
      ['10.0001','10.1',0],['2.0','2_0',0],['1.0~rc1','1.0',-1],['1.0^git1','1.0',1],['1.0^git1','1.01',-1],
      ['1:1.0-1','2.0-1',1],['0:4.15-11.el9_8','4.15-11.el9_8',0],['1.0-2','1.0-10',-1],['1.0','1.0-1',-1],
      ['6.2.8-bp156.2.3.1','6.2.8-bp156',1],['1.99999999999999999999999','1.100000000000000000000000',-1],
    ]);
    for (const bad of ['','1.0-','1.0-1-1','a:1.0','1.0 beta','1.é']) expect(compareVersions('rpm',bad,'1.0')).toBeNull();
  });
  it('apk follows apk-tools: pre-release suffixes below the release, snapshots above',()=>{
    table('apk',[
      ['1.2.3_rc1','1.2.3',-1],['1.2.3','1.2.3_p1',-1],['1.2.3_alpha','1.2.3_beta',-1],['1.2.3_git','1.2.3_hg',-1],
      ['2.40.1_rc1-r0','2.40.1-r0',-1],['1.2.3_p20230101-r1','1.2.3-r5',1],['0.9.3_git20231101-r0','0.9.3-r0',1],
      ['1.36.1-r29','1.36.1-r3',1],['8.2.0','8.2.001',-1],['1.0~1234-r1','1.0~1234-r0',1],['1.2.3a','1.2.3.1',-1],
      ['1.2.3','1.2.3-r0',-1],
    ]);
    for (const bad of ['','0.1bc','0.1_foobar','0.1-r2-r3','1.9.5p2','v1.2.3']) expect(compareVersions('apk',bad,'1.0')).toBeNull();
  });
  it('debian follows policy 5.6.12 epochs, tilde and revisions',()=>{
    table('debian',[
      ['1.0','1.0.0',-1],['1.0','1.0~rc1',1],['1.0~rc1','1.0~rc2',-1],['1.0~','1.0',-1],
      ['1.0-2','1.0-10',-1],['1.0-2','1.1-1',-1],['1:0.9','2.0',1],
      ['1.0beta','1.0+',-1],['1.0beta1','1.0beta',1],['1.02','1.2',0],
      ['1.2.3-r0','1.2.3-r1',-1],['1.2.3~upstream4','1.2.3',-1],
    ]);
  });
  it('maps ecosystems to comparator families like versioning::family_for',()=>{
    expect(versionFamilyForEcosystem('PyPI')).toBe('pep440');
    expect(versionFamilyForEcosystem('Maven')).toBe('maven');
    expect(versionFamilyForEcosystem('RubyGems')).toBe('gem');
    expect(versionFamilyForEcosystem('npm')).toBe('semver');
    expect(versionFamilyForEcosystem('crates.io')).toBe('semver');
    expect(versionFamilyForEcosystem('Go')).toBe('semver');
    expect(versionFamilyForEcosystem('NuGet')).toBe('loose');
    expect(versionFamilyForEcosystem('Packagist')).toBe('loose');
    expect(versionFamilyForEcosystem('Debian:12')).toBe('debian');
    expect(versionFamilyForEcosystem('Alpine:v3.20')).toBe('apk');
    expect(versionFamilyForEcosystem('Hex')).toBe('semver');
    expect(versionFamilyForEcosystem('Pub')).toBe('pub');
    for (const ecosystem of ['Debian','Ubuntu:22.04:LTS']) expect(versionFamilyForEcosystem(ecosystem)).toBe('debian');
    for (const ecosystem of ['Alpine','Wolfi','Chainguard','MinimOS','Alpaquita:23']) expect(versionFamilyForEcosystem(ecosystem)).toBe('apk');
    for (const ecosystem of ['Rocky Linux','Rocky Linux:9','AlmaLinux:9','Red Hat:enterprise_linux:9::appstream','SUSE:Linux Enterprise Server 15 SP5','openSUSE:Leap 15.5','Mageia','Photon OS','Azure Linux:3','openEuler:22.03-LTS-SP4']) expect(versionFamilyForEcosystem(ecosystem)).toBe('rpm');
    // Map lookups never reach Object.prototype names.
    for (const ecosystem of ['Debianish','Rocky Linuxish','Linux','Echo','constructor','toString:1','__proto__']) expect(versionFamilyForEcosystem(ecosystem)).toBeNull();
  });
  it('agrees with the Rust comparators on every shared vector',()=>{
    type Comparison = { family?: string; ecosystem?: string; a: string; b: string; expected: number | null };
    expect(sharedVectors.families.length).toBeGreaterThan(0);
    for (const { rangeType, ecosystem, family } of sharedVectors.families) {
      expect(versionFamilyFor(rangeType, ecosystem), `family_for(${rangeType}, ${ecosystem})`).toBe(family);
    }
    const comparisons: Comparison[] = sharedVectors.comparisons;
    expect(comparisons.length).toBeGreaterThan(0);
    for (const { family: named, ecosystem, a, b, expected } of comparisons) {
      const family = (named ?? versionFamilyFor('ECOSYSTEM', ecosystem!)) as VersionFamily;
      expect(family, `${ecosystem} has a family`).not.toBeNull();
      const mirrored = expected === null || expected === 0 ? expected : -expected;
      expect(compareVersions(family, a, b), `${family}: ${a} vs ${b}`).toBe(expected);
      expect(compareVersions(family, b, a), `${family}: ${b} vs ${a} (mirrored)`).toBe(mirrored);
    }
  });
});
describe('ecosystem-wide upgrade candidates',()=>{
  const ecosystemVuln=(ecosystem:string,events:Array<Record<string,string>>,changes:Partial<Vulnerability>={}):Vulnerability=>
    vuln(events,{ecosystem,lockfile:`/repo/${ecosystem}.lock`,affectedEvidence:{ecosystem,packageName:'leaf',records:[{package:{ecosystem,name:'leaf'},ranges:[{type:'ECOSYSTEM',events}]}]},...changes});
  it('evaluates PyPI ECOSYSTEM ranges with pep440 semantics',()=>{
    const v=ecosystemVuln('PyPI',[{introduced:'0'},{fixed:'1.0.1'}]);
    expect(affectedBy(v,'1.0')).toBe(true);
    expect(affectedBy(v,'1.0.1')).toBe(false);
    expect(affectedBy(ecosystemVuln('PyPI',[{introduced:'1.0a1'},{fixed:'1.0'}]),'1.0.dev1')).toBe(false);
    expect(affectedBy(ecosystemVuln('PyPI',[{introduced:'1.0a1'},{fixed:'1.0'}]),'1.0rc1')).toBe(true);
  });
  it('offers the lowest qualifying fixed version for non-npm ecosystems without an npm command',()=>{
    const group=upgradeGroups([ecosystemVuln('PyPI',[{introduced:'0'},{fixed:'1.2.0'},{fixed:'1.0.1'}])])[0];
    expect(group.candidate).toBe('1.0.1');
    expect(group.classification).toBe('patch');
    expect(group.command).toBeNull();
    expect(group.checklist).toContain('Advisory candidate 1.0.1');
  });
  it('offers Maven and RubyGems candidates via their own comparators',()=>{
    expect(upgradeGroups([ecosystemVuln('Maven',[{introduced:'0'},{fixed:'1.0.1'}])])[0].candidate).toBe('1.0.1');
    expect(upgradeGroups([ecosystemVuln('RubyGems',[{introduced:'0'},{fixed:'1.0.1'}])])[0].candidate).toBe('1.0.1');
    expect(upgradeGroups([ecosystemVuln('NuGet',[{introduced:'0'},{fixed:'1.0.0.1'}])])[0].candidate).toBe('1.0.0.1');
  });
  it('offers no candidate when the installed version already clears every supplied fix',()=>{
    expect(upgradeGroups([ecosystemVuln('PyPI',[{introduced:'0'},{fixed:'0.9.0'}])])[0].candidate).toBeNull();
  });
  it('stays undetermined for ecosystems without a comparator',()=>{
    const kernel=ecosystemVuln('Linux',[{introduced:'0'},{fixed:'1.0.1'}]);
    expect(affectedBy(kernel,'1.0.0')).toBeNull();
    expect(upgradeGroups([kernel])[0].candidate).toBeNull();
  });
  it('evaluates RPM ranges with rpm ordering and offers the lowest clearing fix',()=>{
    const rocky=ecosystemVuln('Rocky Linux:9',[{introduced:'0'},{fixed:'0:4.15-11.el9_8'}],{installedVersion:'4.15-10.el9_8'});
    expect(affectedBy(rocky,'4.15-10.el9_8')).toBe(true);
    expect(affectedBy(rocky,'4.15~rc1-20.el9')).toBe(true);
    expect(affectedBy(rocky,'4.15-11.el9_8')).toBe(false);
    expect(affectedBy(rocky,'1:1.0-1')).toBe(false);
    expect(upgradeGroups([rocky])[0].candidate).toBe('0:4.15-11.el9_8');
  });
  it('evaluates apk ranges with apk-tools ordering, a release candidate of the fix still affected',()=>{
    const wolfi=ecosystemVuln('Wolfi',[{introduced:'0'},{fixed:'1.2.3-r1'}]);
    expect(affectedBy(wolfi,'1.2.3-r0')).toBe(true);
    expect(affectedBy(wolfi,'1.2.3-r1')).toBe(false);
    const alpine=ecosystemVuln('Alpine:v3.20',[{introduced:'0'},{fixed:'2.40.1-r0'}]);
    expect(affectedBy(alpine,'2.40.1_rc1-r0')).toBe(true);
    expect(affectedBy(alpine,'2.40.1_p20230101-r1')).toBe(false);
  });
  it('evaluates Maven ranges past unknown qualifiers',()=>{
    const guava=ecosystemVuln('Maven',[{introduced:'0'},{fixed:'32.0.0-android'}],{installedVersion:'31.1-jre'});
    expect(affectedBy(guava,'31.1-jre')).toBe(true);
    expect(affectedBy(guava,'32.0.0-jre')).toBe(false);
  });
});
