import { Box, Database, Search, ShieldCheck } from "lucide-react";
import { useDeferredValue, useEffect, useState, type JSX } from "react";
import { Select } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { ResultPagination } from "../components/workbench/ResultPagination";
import { ServerPageState } from "../components/workbench/ServerPageState";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { useServerPage } from "../lib/serverPagination";
import type { CanonicalRun, InventoryComponentView, InventoryPage as InventoryPageResult, ResultPageQuery } from "../lib/types";

const loadRuns = (_id: string, query: ResultPageQuery) => api.listInventoryRuns(query);

export function InventoryPage(): JSX.Element {
  const [runId, setRunId] = useState("");
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const runs = useServerPage<CanonicalRun>("inventory", {}, loadRuns);
  const components = useServerPage<InventoryComponentView, InventoryPageResult>(
    runId || null, { search: deferredQuery }, api.loadInventoryPage,
  );
  const inventory = components.data;

  useEffect(() => {
    if (!runs.data) return;
    const available = runs.data.items;
    setRunId(current => available.some(run => run.id === current) ? current : available[0]?.id ?? "");
  }, [runs.data]);

  return (
    <ToolPage title="Inventory" description="Inspect every component a completed scan identified—even when no vulnerability matched—and trace each identity back to its artifact evidence.">
      <section className="rounded-sm border border-border bg-surface-secondary p-4">
        <label className="block text-[12px] text-text-secondary">Completed inventory run
          <Select className="mt-1 w-full" value={runId} onChange={event => setRunId(event.target.value)} disabled={runs.loading || !runs.items.length}>
            {runId && !runs.items.some(run => run.id === runId) && <option value={runId}>Selected inventory · {runId}</option>}
            {runs.items.map(run => <option key={run.id} value={run.id}>{run.kind} · {run.targetLabel} · {new Date(run.updatedAtMs).toLocaleString()}</option>)}
          </Select>
        </label>
        <ServerPageState page={runs} />
        {runs.total > runs.pageSize && <ResultPagination label="inventory runs" pagination={runs} onPageChange={runs.setPage} />}
        {inventory && <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-text-muted">
          <span className="inline-flex items-center gap-1"><Box size={12} aria-hidden="true" />{inventory.total.toLocaleString()} components</span>
          <span className="inline-flex items-center gap-1"><Database size={12} aria-hidden="true" />{inventory.providerSnapshotCount} immutable provider snapshots</span>
          <span className="font-mono">{inventory.runKind} · {inventory.runId}</span>
        </div>}
      </section>

      {runs.data?.total === 0 && <InlineState tone="empty" title="No completed inventory runs yet" description="Run a Dependency, Binary, or Image scan. Unflagged components remain visible here." />}
      {runId && <section className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
        <ResultsToolbar countLabel={inventory ? `${inventory.filteredTotal.toLocaleString()} of ${inventory.total.toLocaleString()} components` : components.error ? "Inventory unavailable" : "Loading components…"}
          search={<label className="relative min-w-0">
            <span className="sr-only">Search inventory</span>
            <Search size={13} aria-hidden="true" className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
            <input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search package, purl, CPE, or advisory…" className="w-72 max-w-full rounded-sm border border-border bg-surface-primary py-1.5 pl-8 pr-2 text-[12px] text-text-primary placeholder:text-text-muted" />
          </label>}
        />
        <ServerPageState page={components} />
        {inventory?.filteredTotal === 0 && <InlineState compact tone="empty" title={inventory.total ? "No components match this search" : "No components were recorded in this run"} />}
        <div className="divide-y divide-border">
          {components.items.map(component => (
                <article key={component.id} className="p-4" style={{ contentVisibility: "auto", containIntrinsicSize: "220px" }}>
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h2 className="text-[14px] font-semibold text-text-primary">{component.name} <span className="font-normal text-text-secondary">{component.version ?? "version unknown"}</span></h2>
                      <p className="mt-1 break-all font-mono text-[10px] text-text-muted">{component.purl ?? component.id}</p>
                    </div>
                    <span className={`inline-flex items-center gap-1 text-[11px] ${component.advisoryIds.length ? "text-warning" : "text-success"}`}>
                      <ShieldCheck size={13} aria-hidden="true" />{component.advisoryIds.length ? `${component.advisoryIds.length} advisory matches` : "No advisory match recorded"}
                    </span>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2 text-[10px] text-text-muted">
                    {component.ecosystem && <span className="rounded-full border border-border px-2 py-0.5">{component.ecosystem}</span>}
                    {component.supplier && <span className="rounded-full border border-border px-2 py-0.5">{component.supplier}</span>}
                    {component.aliases.map((alias) => <span key={alias} className="rounded-full border border-border px-2 py-0.5">{alias}</span>)}
                    {component.cpes.map((cpe) => <span key={cpe} className="rounded-full border border-border px-2 py-0.5 font-mono">{cpe}</span>)}
                    {component.advisoryIds.map((advisory) => <span key={advisory} className="rounded-full border border-warning-subtle px-2 py-0.5 text-warning">{advisory}</span>)}
                  </div>
                  <details className="mt-3 rounded-sm border border-border bg-surface-primary">
                    <summary className="cursor-pointer px-3 py-2 text-[11px] text-text-secondary">{component.identities.length} identity evidence records</summary>
                    <div className="divide-y divide-border border-t border-border">
                      {component.identities.map((identity, index) => (
                        <div key={`${identity.artifactId}-${index}`} className="grid gap-1 px-3 py-2 text-[11px] min-[720px]:grid-cols-[9rem_1fr_7rem]">
                          <span className="font-mono text-text-muted">{identity.method}</span>
                          <span className="min-w-0 break-all text-text-secondary">{identity.value}<span className="mt-0.5 block text-[10px] text-text-muted">{identity.artifactPath}</span></span>
                          <span className="text-text-muted">{Math.round(identity.confidence * 100)}% confidence</span>
                        </div>
                      ))}
                    </div>
                  </details>
                </article>
          ))}
        </div>
        <ResultPagination label="inventory components" pagination={components} onPageChange={components.setPage} />
      </section>}
    </ToolPage>
  );
}
