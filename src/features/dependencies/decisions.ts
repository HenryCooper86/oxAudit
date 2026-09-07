import type { DependencyPath, Vulnerability } from '../../lib/types';

export type UpgradeGroup = {
  key: string;
  advisories: Vulnerability[];
  paths: DependencyPath[];
  candidate: string | null;
  classification: string;
  command: string | null;
  checklist: string;
};
type Version = [number, number, number];
function numeric(value: unknown): Version | null {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value)) return null;
  const parts = value.split('.').map(Number);
  return parts.every(Number.isSafeInteger) ? parts as Version : null;
}
function compare(a: Version, b: Version) { return a[0]-b[0] || a[1]-b[1] || a[2]-b[2]; }

/** OSV evaluation over matching records: versions union ranges, with sorted events
 * and an independent (union) limit gate. Unknown in any supplied semantics blocks proof. */
export function affectedBy(v: Vulnerability, candidate: string): boolean | null {
  const version = numeric(candidate);
  const evidence = v.affectedEvidence;
  if (!version || v.ecosystem !== 'npm' || !evidence || evidence.ecosystem !== v.ecosystem || evidence.packageName !== v.packageName || !evidence.records.length) return null;
  let affected = false;
  for (const record of evidence.records) {
    if (record.package?.ecosystem !== v.ecosystem || record.package?.name !== v.packageName) return null;
    if (record.versions !== undefined && !Array.isArray(record.versions)) return null;
    for (const value of record.versions ?? []) {
      const parsed = numeric(value);
      if (!parsed) return null;
      if (compare(version, parsed) === 0) affected = true;
    }
    if (record.ranges !== undefined && !Array.isArray(record.ranges)) return null;
    if (!(record.ranges?.length || record.versions?.length)) return null;
    for (const range of record.ranges ?? []) {
      if (!range || range.type !== 'SEMVER' || !Array.isArray(range.events) || !range.events.length) return null;
      const transitions: Array<{ kind: string; version: Version }> = [];
      const limits: Array<Version | '*'> = [];
      for (const event of range.events) {
        if (!event || typeof event !== 'object' || Object.keys(event).length !== 1) return null;
        const [kind, value] = Object.entries(event)[0];
        if (!['introduced','fixed','last_affected','limit'].includes(kind)) return null;
        if (kind === 'limit' && value === '*') { limits.push('*'); continue; }
        const parsed = kind === 'introduced' && value === '0' ? [-1,0,0] as Version : numeric(value);
        if (!parsed) return null;
        if (kind === 'limit') limits.push(parsed);
        else transitions.push({kind,version:parsed});
      }
      if (!transitions.some(e=>e.kind==='introduced') || (transitions.some(e=>e.kind==='fixed') && transitions.some(e=>e.kind==='last_affected'))) return null;
      transitions.sort((a,b)=>compare(a.version,b.version));
      // Simultaneous status transitions are ambiguous; do not guess tie order.
      if (transitions.some((e,i)=>i>0 && compare(e.version,transitions[i-1].version)===0)) return null;
      let included = false;
      for (const event of transitions) {
        const order=compare(version,event.version);
        if (event.kind==='introduced' && order>=0) included=true;
        if (event.kind==='fixed' && order>=0) included=false;
        if (event.kind==='last_affected' && order>0) included=false;
      }
      const beforeLimit=!limits.length || limits.some(limit=>limit==='*' || compare(version,limit)<0);
      if (beforeLimit && included) affected=true;
    }
  }
  return affected;
}
function suppliedFixes(v: Vulnerability): string[] {
  const fixes: string[]=[];
  for (const record of v.affectedEvidence?.records ?? []) {
    if (!record || !Array.isArray(record.ranges)) continue;
    for (const range of record.ranges) {
      if (!range || !Array.isArray(range.events)) continue;
      for (const event of range.events) {
        if (event && typeof event.fixed==='string' && numeric(event.fixed)) fixes.push(event.fixed);
      }
    }
  }
  return fixes;
}
const safeName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
function directCommand(group: UpgradeGroup): string | null {
  const v=group.advisories[0];
  if (!group.candidate || !group.paths.length || !v.lockfile.endsWith('/package-lock.json')) return null;
  if (group.advisories.some(a=>a.occurrence?.localWorkspace || a.occurrence?.status!=='available' || a.occurrence.warnings.length>0)) return null;
  const first=group.paths[0].chain[0];
  if (!first || !safeName.test(first.name) || first.name!==v.packageName) return null;
  const flag={runtime:'--save-prod',dev:'--save-dev',optional:'--save-optional'}[first.dependencyType];
  if (!flag || group.paths.some(p=>p.chain.length!==1 || p.chain[0].name!==first.name || p.chain[0].dependencyType!==first.dependencyType || p.chain[0].installPath!==v.occurrence?.installPath || !/^[~^]?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(p.chain[0].declared))) return null;
  const workspace=group.paths[0].workspace;
  if (workspace && (!/^[a-zA-Z0-9_@./-]+$/.test(workspace) || workspace.startsWith('/') || workspace.split('/').some(p=>!p || p==='..' || p==='.'))) return null;
  return `npm install --ignore-scripts ${flag}${workspace ? ` --workspace '${workspace}'` : ''} -- '${first.name}@${group.candidate}'`;
}
export function vulnerabilityKey(v: Vulnerability): string {
  return JSON.stringify([v.id,v.ecosystem,v.packageName,v.installedVersion,v.lockfile,v.occurrence?.installPath ?? null]);
}
export function upgradeGroups(vulnerabilities: Vulnerability[]): UpgradeGroup[] {
  const groups=new Map<string,UpgradeGroup>();
  for (const v of vulnerabilities) {
    const paths=v.occurrence?.paths.length ? v.occurrence.paths : [null];
    for (const path of paths) {
      const key=JSON.stringify([v.ecosystem,v.packageName,v.installedVersion,v.lockfile,v.occurrence?.installPath ?? null,path?.workspace ?? null,path?.entryPoint ?? null]);
      let group=groups.get(key);
      if (!group) { group={key,advisories:[],paths:[],candidate:null,classification:'unknown',command:null,checklist:''};groups.set(key,group); }
      if (!group.advisories.includes(v)) group.advisories.push(v);
      if (path && !group.paths.some(p=>JSON.stringify(p)===JSON.stringify(path))) group.paths.push(path);
    }
  }
  for (const group of groups.values()) {
    const v=group.advisories[0], installed=numeric(v.installedVersion);
    if (installed && group.advisories.every(advisory=>affectedBy(advisory,v.installedVersion)===true)) {
      const fixes=[...new Set(group.advisories.flatMap(suppliedFixes))].sort((a,b)=>compare(numeric(a)!,numeric(b)!));
      group.candidate=fixes.find(fix=>compare(numeric(fix)!,installed)>0 && group.advisories.every(advisory=>affectedBy(advisory,fix)===false)) ?? null;
      if (group.candidate) {
        const next=numeric(group.candidate)!;
        group.classification=next[0]!==installed[0]?'major':next[1]!==installed[1]?'minor':'patch';
      }
    }
    group.command=directCommand(group);
    const origin=group.paths[0];
    group.checklist=[
      `Review ${v.packageName}@${v.installedVersion} in ${v.lockfile} (${v.occurrence?.installPath ?? 'installation path unknown'}).`,
      origin ? `Review manifest ${origin.workspace || 'root'} and update entry point ${origin.entryPoint}${group.paths.some(p=>p.chain.length>1)?'; select a parent release that updates the affected transitive package':''}.` : 'Establish the dependency chain and direct manifest entry point; relationship evidence is unknown.',
      group.candidate ? `Advisory candidate ${group.candidate} clears the supplied supported ranges; verify release availability and project compatibility.` : 'Manual decision: no supplied candidate is proven to clear all advisory ranges. Review each advisory fix.',
      `Related advisories: ${[...new Set(group.advisories.map(a=>a.id))].join(', ')}.`,
      'Review manifest and lockfile changes, run project checks, then Recheck dependencies in oxAudit.'
    ].join('\n');
  }
  return [...groups.values()];
}
