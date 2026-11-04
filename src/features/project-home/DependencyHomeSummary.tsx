import { useEffect, useState } from "react";
import { Button } from "../../components/ui";
import { errorMessage } from "../../lib/commandError";
import type { CanonicalRun } from "../../lib/types";
import { loadDependencyHomeSummary, type SavedDependencySummary } from "./dependencySummary";

export function DependencyHomeSummary({ run, revision, refreshing }: {
  run: CanonicalRun | null;
  revision: number;
  refreshing: boolean;
}) {
  const [retry, setRetry] = useState(0);
  const key = JSON.stringify([run?.id, run?.targetLabel, run?.state, revision, refreshing, retry]);
  const [lifetime, setLifetime] = useState({ key, generation: 0 });
  let generation = lifetime.generation;
  if (lifetime.key !== key) {
    generation += 1;
    setLifetime({ key, generation });
  }
  const request = JSON.stringify([key, generation]);
  const [response, setResponse] = useState<{ request: string; data?: SavedDependencySummary; error?: string } | null>(null);
  useEffect(() => {
    if (!run || refreshing) return;
    let disposed = false;
    void loadDependencyHomeSummary(run).then(
      data => { if (!disposed) setResponse({ request, data }); },
      cause => { if (!disposed) setResponse({ request, error: errorMessage(cause, "Saved dependency summary could not be loaded.") }); },
    );
    return () => { disposed = true; };
  }, [refreshing, request, run]);
  const settled = response?.request === request ? response : null;

  return <section aria-label="Saved dependency summary" className="space-y-1">
    {refreshing ? <p role="status">Loading saved dependency summary…</p>
      : !run ? <><p>No completed dependency scan is available.</p><p>Dependency findings: unknown.</p></>
      : settled?.data ? <div role="status">
        <p>{settled.data.total.toLocaleString()} vulnerabilities · {settled.data.critical.toLocaleString()} critical · {settled.data.high.toLocaleString()} high</p>
        <p>Advisory coverage: {settled.data.coverage} · {settled.data.packages.toLocaleString()} packages</p>
        <p className="text-text-muted">Counts reflect the last completed dependency run.</p>
      </div>
      : settled?.error ? <>
        <p>Dependency findings: unknown.</p>
        <p role="alert" className="text-error">Saved dependency summary unavailable: {settled.error}</p>
        <Button variant="outline" onClick={() => setRetry(value => value + 1)}>Retry dependency summary</Button>
      </>
      : <p role="status">Loading saved dependency summary…</p>}
  </section>;
}
