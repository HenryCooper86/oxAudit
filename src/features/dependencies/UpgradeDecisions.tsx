import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { DependencyScanResult, Vulnerability } from '../../lib/types';
import { upgradeGroups } from './decisions';
import { usePagination } from '../../lib/pagination';
import { ResultPagination } from '../../components/workbench/ResultPagination';
const noAdvisories: Vulnerability[]=[];

const control='rounded-sm border border-border bg-surface-tertiary px-2.5 py-1.5 text-[12px] text-text-primary hover:bg-surface-active disabled:opacity-50';
function timestamp(value: number | null | undefined) { return value == null ? 'unknown' : new Date(value).toLocaleString(); }
export function UpgradeDecisions({result,onSelect,onRecheck,disabled}: {result:DependencyScanResult;onSelect:(v:Vulnerability)=>void;onRecheck:()=>void;disabled:boolean}) {
  const groups=useMemo(()=>upgradeGroups(result.vulnerabilities),[result.vulnerabilities]);
  const [selectedKey,setSelectedKey]=useState<string|null>(null);
  const selected=groups.find(g=>g.key===selectedKey) ?? groups[0];
  const groupPagination=usePagination(groups,50,selected ? groups.indexOf(selected) : -1);
  const advisoryPagination=usePagination(selected?.advisories ?? noAdvisories);
  const copyScope=useMemo(()=>({}),[result,result.summary.runId,selected?.key]);
  const [copyFeedback,setCopyFeedback]=useState<{scope:object;message:string}|null>(null);
  const copyRequest=useRef(0);
  useLayoutEffect(()=>()=>{copyRequest.current+=1;},[copyScope]);
  const copyStatus=copyFeedback?.scope===copyScope ? copyFeedback.message : '';
  const enrichment=result.summary.enrichment;
  async function copy(text:string,kind:string) {
    const request=++copyRequest.current;
    const publish=(message:string)=>{
      if(copyRequest.current===request) setCopyFeedback({scope:copyScope,message});
    };
    try { await navigator.clipboard.writeText(text);publish(`Copied ${kind}`); }
    catch { publish('Copy unavailable. Select and copy the displayed text.'); }
  }
  return <section aria-label="Dependency upgrade decisions" className="rounded-sm border border-border bg-surface-secondary text-[13px]">
    <div className="space-y-2 border-b border-border p-4 text-text-secondary">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-semibold text-text-primary">Upgrade decisions · {groups.length} groups</h2>
        <button type="button" className={control} disabled={disabled} onClick={onRecheck}>Recheck dependencies</button>
      </div>
      <p>Advisory source: {result.summary.advisorySource ?? 'unknown'} · checked {timestamp(result.summary.advisoryFetchedAtMs)} · coverage {result.summary.advisoryCoverage ?? 'unknown'}.</p>
      {result.summary.inventoryNotes?.map((note,index)=><p className="text-warning" key={`inventory-note-${index}:${note}`}>{note}</p>)}
      {result.summary.advisorySource==='cache' ? <p className="text-warning">Cached advisory evidence has not been refreshed for this check; newer advisories or fixes may exist.</p> : null}
      {result.summary.advisorySource==='local-db' ? <p className="text-warning">Advisory evidence comes from the local database built {timestamp(result.summary.advisoryFetchedAtMs)}; refresh it from the Advisory Database page for newer advisories.</p> : null}
      {result.summary.advisoryNotes?.map((note,index)=><p className="text-warning" key={`advisory-note-${index}:${note}`}>{note}</p>)}
      <p>Optional exploitation enrichment: {enrichment?.status ?? 'unknown'} · checked {timestamp(enrichment?.checkedAtMs)} · public-exploit cache {timestamp(enrichment?.pocCacheUpdatedAtMs)}.</p>
      {enrichment?.status!=='available' ? <p>Absent KEV, EPSS, and public-exploit signals are unknown when enrichment is unavailable, partial, or historical.</p> : null}
      {enrichment?.warnings.map((warning,index)=><p className="text-warning" key={`${index}:${warning}`}>{warning}</p>)}
    </div>
    {selected ? <div className="grid min-[1000px]:grid-cols-[minmax(240px,1fr)_minmax(0,2fr)]">
      <div className="max-h-[34rem] overflow-auto border-b border-border min-[1000px]:border-b-0 min-[1000px]:border-r">
        <table className="w-full text-left"><caption className="sr-only">Upgrade groups by installation and update entry point</caption>
          <thead><tr><th scope="col" className="p-3">Package / location</th><th scope="col" className="p-3">Advisories</th></tr></thead>
          <tbody>{groupPagination.items.map(group=>{const first=group.advisories[0];return <tr key={group.key} className={selected.key===group.key?'bg-surface-active':''}>
            <td className="p-3"><button type="button" aria-pressed={selected.key===group.key} className="w-full text-left text-info" onClick={()=>{setSelectedKey(group.key);setCopyFeedback(null);copyRequest.current+=1;}}>
              <span className="font-mono">{first.packageName}@{first.installedVersion}</span>
              <span className="mt-1 block break-all text-[11px] text-text-muted">{group.paths[0] ? group.paths[0].workspace || 'Root manifest' : 'Workspace unknown'} · {group.paths[0]?.entryPoint ?? 'Entry point unknown'}</span>
              <span className="block break-all text-[11px] text-text-muted">{first.lockfile} · {first.occurrence?.installPath ?? 'Installation path unknown'}</span>
            </button></td><td className="p-3">{new Set(group.advisories.map(a=>a.id)).size}</td>
          </tr>;})}</tbody>
        </table>
        {groupPagination.pageCount>1 ? <ResultPagination pagination={groupPagination} label="upgrade groups" onPageChange={page=>{
          groupPagination.setPage(page);
          setSelectedKey(groups[page*groupPagination.pageSize].key);
          setCopyFeedback(null);copyRequest.current+=1;
        }}/> : null}
      </div>
      <div aria-label="Selected upgrade group" className="min-w-0 space-y-3 p-4 text-text-secondary">
        <h3 className="font-mono text-text-primary">{selected.advisories[0].packageName}@{selected.advisories[0].installedVersion}</h3>
        <p className="break-all">{selected.advisories[0].lockfile}</p>
        <p className="break-all">Installation: {selected.advisories[0].occurrence?.installPath ?? 'unknown'} · Relationships: {selected.advisories[0].occurrence?.status ?? 'unknown'}</p>
        {selected.candidate ? <p className="text-success">Advisory candidate {selected.candidate} clears the supplied supported advisory ranges. Version change: {selected.classification}. Release availability and compatibility are unverified.</p> : <p className="text-warning">Manual decision: no supplied candidate is proven to clear all related advisory ranges.</p>}
        {selected.paths.length ? selected.paths.map((path,index)=><p className="break-all" key={index}>
          {path.workspace || 'Root manifest'} → {path.chain.map(step=>`${step.name}${step.name!==step.packageName?` (${step.packageName})`:''} [${step.dependencyType}]`).join(' → ')}
        </p>) : <p>Dependency chain and direct update entry point are unknown. Review the manifest and parent dependency.</p>}
        {selected.paths.some(path=>path.chain.length>1) ? <p>Update the parent entry point after checking which parent release changes this transitive package.</p> : null}
        {[...new Set(selected.advisories.flatMap(a=>a.occurrence?.warnings ?? []))].map(warning=><p key={warning} className="text-warning">{warning}</p>)}
        {selected.advisories.some(a=>!a.affectedEvidence) ? <p>Matching-package range evidence is unknown. Historical fixed-version strings below require verification or an advisory refresh.</p> : null}
        <ul className="space-y-2">{advisoryPagination.items.map((advisory,index)=><li key={`${advisory.id}:${advisoryPagination.start+index}`}>
          <button type="button" className="text-info underline" onClick={()=>onSelect(advisory)}>Review {advisory.id}</button>
          <span> · Advisory-reported fixed versions: {advisory.fixedVersions.join(', ') || 'unknown / not supplied'}</span>
        </li>)}</ul>
        {advisoryPagination.pageCount>1 ? <ResultPagination pagination={advisoryPagination} label="upgrade group advisories" onPageChange={advisoryPagination.setPage}/> : null}
        {selected.command ? <><p>Copy for review and run manually from the lockfile directory. This updates the recorded direct declaration with lifecycle scripts disabled.</p>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-sm bg-surface-tertiary p-3 font-mono text-[12px]">{selected.command}</pre>
          <button type="button" className={control} onClick={()=>void copy(selected.command!,'npm command')}>Copy npm command</button></> : null}
        <pre className="max-h-[24rem] overflow-auto whitespace-pre-wrap break-words rounded-sm bg-surface-tertiary p-3 text-[12px]">{selected.checklist}</pre>
        <button type="button" className={control} onClick={()=>void copy(selected.checklist,'remediation checklist')}>Copy remediation checklist</button>
        {copyStatus ? <p role="status">{copyStatus}</p> : null}
      </div>
    </div> : <p className="p-4 text-text-muted">No advisory groups in this result.</p>}
  </section>;
}
