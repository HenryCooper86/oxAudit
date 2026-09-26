import { CheckCircle2, Database, RefreshCw, WifiOff } from "lucide-react";
import { useCallback, useEffect, useState, type JSX } from "react";
import { openUrl } from "../lib/opener";
import { Button } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import type { DataSourceStatus } from "../lib/types";

export function DataSourcesPage(): JSX.Element {
  const [sources, setSources] = useState<DataSourceStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setSources(await api.listDataSources());
    } catch (cause) {
      setError(String(cause));
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  const refresh = async (providerId: string) => {
    setRefreshing(providerId);
    setError(null);
    try {
      const next = await api.refreshDataSource(providerId);
      setSources((current) =>
        (current ?? []).map((source) => (source.id === providerId ? next : source)),
      );
    } catch (cause) {
      setError(String(cause));
    } finally {
      setRefreshing(null);
    }
  };

  return (
    <ToolPage
      title="Data Sources"
      description="See exactly which advisory data oxAudit uses, validate new immutable snapshots, and know what remains available offline."
    >
      {!sources && !error && <InlineState tone="running" title="Loading provider registry" />}
      {error && <InlineState tone="error" title="A data-source operation failed" description={error} />}
      {sources && (
        <div className="grid gap-3 min-[820px]:grid-cols-2">
          {sources.map((source) => (
            <article key={source.id} className="rounded-sm border border-border bg-surface-secondary p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex min-w-0 items-start gap-3">
                  <Database size={17} aria-hidden="true" className="mt-0.5 shrink-0 text-accent" />
                  <div className="min-w-0">
                    <h2 className="text-[14px] font-semibold text-text-primary">{source.name}</h2>
                    <p className="mt-0.5 font-mono text-[10px] text-text-muted">{source.id}</p>
                  </div>
                </div>
                <ProviderState source={source} />
              </div>
              <p className="mt-3 text-[12px] leading-relaxed text-text-secondary">{source.limitation}</p>
              <dl className="mt-3 grid grid-cols-2 gap-3 text-[11px]">
                <Item label="Records" value={source.recordCount?.toLocaleString() ?? "Not measured"} />
                <Item label="Last refresh" value={source.fetchedAtMs ? new Date(source.fetchedAtMs).toLocaleString() : "Never"} />
                <Item label="Licence / terms" value={source.license} />
                <Item label="Validation" value={source.validation} />
              </dl>
              {source.contentSha256 && <p className="mt-3 truncate font-mono text-[10px] text-text-muted" title={source.contentSha256}>SHA-256 {source.contentSha256}</p>}
              <div className="mt-4 flex flex-wrap gap-2">
                <Button type="button" onClick={() => void refresh(source.id)} disabled={refreshing !== null} variant="outline" size="md">
                  <RefreshCw size={13} aria-hidden="true" />
                  {refreshing === source.id ? "Refreshing…" : "Refresh safely"}
                </Button>
                <Button type="button" onClick={() => void openUrl(source.termsUrl)} variant="ghost" size="md">Terms & provenance</Button>
              </div>
            </article>
          ))}
        </div>
      )}
    </ToolPage>
  );
}

function ProviderState({ source }: { source: DataSourceStatus }): JSX.Element {
  if (source.state === "offlineReady") {
    return <span className="inline-flex shrink-0 items-center gap-1 text-[11px] text-success"><CheckCircle2 size={12} aria-hidden="true" />Offline ready</span>;
  }
  if (source.state === "onlineCached") {
    return <span className="inline-flex shrink-0 items-center gap-1 text-[11px] text-info"><CheckCircle2 size={12} aria-hidden="true" />Health cached</span>;
  }
  return <span className="inline-flex shrink-0 items-center gap-1 text-[11px] text-text-muted"><WifiOff size={12} aria-hidden="true" />Not refreshed</span>;
}

function Item({ label, value }: { label: string; value: string }): JSX.Element {
  return <div><dt className="font-semibold uppercase tracking-[0.08em] text-text-muted">{label}</dt><dd className="mt-1 leading-relaxed text-text-secondary">{value}</dd></div>;
}
