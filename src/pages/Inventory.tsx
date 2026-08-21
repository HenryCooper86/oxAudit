import { Box, Database, Search, ShieldCheck } from "lucide-react";
import { useDeferredValue, useEffect, useMemo, useState, type JSX } from "react";
import { Button, Select } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import type { CanonicalRun, InventoryView } from "../lib/types";

const INVENTORY_RUN_KINDS = new Set(["dependencies", "binary", "firmware", "import"]);
const PAGE_SIZE = 100;

export function InventoryPage(): JSX.Element {
  const [runs, setRuns] = useState<CanonicalRun[] | null>(null);
  const [runId, setRunId] = useState("");
  const [inventory, setInventory] = useState<InventoryView | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let disposed = false;
    void api.listCanonicalRuns(undefined, 100).then((loaded) => {
      if (disposed) return;
      const available = loaded.filter((run) => run.state === "completed" && INVENTORY_RUN_KINDS.has(run.kind));
      setRuns(available);
      setRunId((current) => current || available[0]?.id || "");
    }).catch((cause) => {
      if (!disposed) setError(String(cause));
    });
    return () => { disposed = true; };
  }, []);

  useEffect(() => {
    let disposed = false;
    if (!runId) {
      setInventory(null);
      return;
    }
    setLoading(true);
    setError(null);
    void api.loadInventory(runId).then((loaded) => {
      if (!disposed) setInventory(loaded);
    }).catch((cause) => {
      if (!disposed) {
        setInventory(null);
        setError(String(cause));
      }
    }).finally(() => {
      if (!disposed) setLoading(false);
    });
    return () => { disposed = true; };
  }, [runId]);

  const deferredQuery = useDeferredValue(query);
  const visible = useMemo(() => {
    const normalized = deferredQuery.trim().toLowerCase();
    if (!normalized) return inventory?.components ?? [];
    return (inventory?.components ?? []).filter((component) =>
      [
        component.name,
        component.version,
        component.supplier,
        component.ecosystem,
        component.purl,
        ...component.aliases,
        ...component.cpes,
        ...component.advisoryIds,
      ].filter(Boolean).join(" ").toLowerCase().includes(normalized),
    );
  }, [deferredQuery, inventory]);
  const pageCount = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
  const activePage = Math.min(page, pageCount - 1);
  const pageComponents = visible.slice(activePage * PAGE_SIZE, (activePage + 1) * PAGE_SIZE);

  return (
    <ToolPage
      title="Inventory"
      description="Inspect every component a completed scan identified—even when no vulnerability matched—and trace each identity back to its artifact evidence."
    >
      <section className="rounded-sm border border-border bg-surface-secondary p-4">
        <label className="block text-[12px] text-text-secondary">Completed inventory run
          <Select className="mt-1 w-full" value={runId} onChange={(event) => { setRunId(event.target.value); setPage(0); }} disabled={!runs?.length}>
            {(runs ?? []).map((run) => <option key={run.id} value={run.id}>{run.kind} · {run.targetLabel} · {new Date(run.updatedAtMs).toLocaleString()}</option>)}
          </Select>
        </label>
        {inventory && (
          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-text-muted">
            <span className="inline-flex items-center gap-1"><Box size={12} aria-hidden="true" />{inventory.components.length} components</span>
            <span className="inline-flex items-center gap-1"><Database size={12} aria-hidden="true" />{inventory.providerSnapshotCount} immutable provider snapshots</span>
            <span className="font-mono">{inventory.runKind} · {inventory.runId}</span>
          </div>
        )}
      </section>

      {!runs && !error && <InlineState tone="running" title="Loading durable inventories" />}
      {runs?.length === 0 && <InlineState tone="empty" title="No completed inventory runs yet" description="Run a Dependency or Binary scan. Inventory is persisted before advisory enrichment, so unflagged components remain visible here." />}
      {loading && <InlineState compact tone="running" title="Loading component evidence" />}
      {error && <InlineState tone="error" title="Inventory is unavailable" description={error} />}
      {inventory && !loading && (
        <section className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
          <ResultsToolbar
            countLabel={`${visible.length} of ${inventory.components.length} components`}
            search={
              <label className="relative min-w-0">
                <span className="sr-only">Search inventory</span>
                <Search size={13} aria-hidden="true" className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
                <input value={query} onChange={(event) => { setQuery(event.target.value); setPage(0); }} placeholder="Search package, purl, CPE, or advisory…" className="w-72 max-w-full rounded-sm border border-border bg-surface-primary py-1.5 pl-8 pr-2 text-[12px] text-text-primary placeholder:text-text-muted" />
              </label>
            }
          />
          {visible.length === 0 ? <InlineState compact tone="empty" title="No components match this search" /> : (
            <div className="divide-y divide-border">
              {pageComponents.map((component) => (
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
          )}
          {visible.length > PAGE_SIZE && (
            <footer className="flex items-center justify-between gap-3 border-t border-border px-4 py-3 text-[11px] text-text-muted">
              <span>Page {activePage + 1} of {pageCount} · up to {PAGE_SIZE} components rendered at once</span>
              <div className="flex gap-2">
                <Button type="button" variant="outline" size="sm" disabled={activePage === 0} onClick={() => setPage((current) => Math.max(0, current - 1))}>Previous</Button>
                <Button type="button" variant="outline" size="sm" disabled={activePage + 1 >= pageCount} onClick={() => setPage((current) => Math.min(pageCount - 1, current + 1))}>Next</Button>
              </div>
            </footer>
          )}
        </section>
      )}
    </ToolPage>
  );
}
