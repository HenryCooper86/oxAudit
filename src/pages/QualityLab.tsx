import { FlaskConical, RefreshCw, TriangleAlert } from "lucide-react";
import { useCallback, useEffect, useState, type JSX } from "react";
import { Button } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import type { QualityStatus } from "../lib/types";

export function QualityLabPage(): JSX.Element {
  const [status, setStatus] = useState<QualityStatus | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      setStatus(await api.qualityStatus());
    } catch (cause) {
      setError(String(cause));
    } finally {
      setRunning(false);
    }
  }, []);

  useEffect(() => {
    void run();
  }, [run]);

  return (
    <ToolPage
      title="Quality Lab"
      description="Run pinned ground truth locally and inspect passes, misses, false positives, and limitations—without a network connection or model."
      context={<Button type="button" onClick={() => void run()} disabled={running} variant="outline" size="md"><RefreshCw size={13} aria-hidden="true" />{running ? "Running…" : "Run benchmark"}</Button>}
    >
      {running && !status && <InlineState tone="running" title="Running the deterministic benchmark" />}
      {error && <InlineState tone="error" title="Benchmark failed" description={error} />}
      {status && (
        <>
          <section aria-label="Benchmark metrics" className="grid grid-cols-2 overflow-hidden rounded-sm border border-border bg-surface-secondary min-[720px]:grid-cols-6">
            <Metric label="Corpus" value={String(status.corpusTargets)} />
            <Metric label="Passed" value={`${status.passedTargets}/${status.corpusTargets}`} />
            <Metric label="Precision" value={percent(status.precision)} />
            <Metric label="Recall" value={percent(status.recall)} />
            <Metric label="Misses / FP" value={`${status.falseNegatives} / ${status.falsePositives}`} />
            <Metric label="Runtime" value={`${status.runtimeMs} ms`} />
          </section>
          <section className="rounded-sm border border-border bg-surface-secondary p-4">
            <div className="flex items-start gap-3">
              <FlaskConical className="mt-0.5 shrink-0 text-accent" size={17} aria-hidden="true" />
              <div>
                <h2 className="text-[14px] font-semibold text-text-primary">{status.suiteId} · v{status.suiteVersion}</h2>
                <p className="mt-1 text-[12px] leading-relaxed text-text-secondary">{status.description}</p>
              </div>
            </div>
          </section>
          {(status.misses.length > 0 || status.unexpected.length > 0) && (
            <section className="rounded-sm border border-warning-subtle bg-warning-subtle p-4">
              <h2 className="flex items-center gap-2 text-[13px] font-semibold text-text-primary"><TriangleAlert size={14} aria-hidden="true" />Regressions</h2>
              <ul className="mt-2 space-y-1 font-mono text-[11px] text-text-secondary">
                {[...status.misses, ...status.unexpected].map((item) => <li key={item}>{item}</li>)}
              </ul>
            </section>
          )}
          <InlineState tone="unavailable" title="Scope limitation" description={status.limitation} />
          <InlineState
            tone={status.regression ? "error" : "empty"}
            title={status.regression ? "Regression from the previous saved run" : "No measured regression from the previous saved run"}
            description={
              status.previousPrecision === null && status.previousRecall === null
                ? "This result established the first local baseline."
                : `Previous precision ${percent(status.previousPrecision)} · previous recall ${percent(status.previousRecall)}`
            }
          />
        </>
      )}
    </ToolPage>
  );
}

function Metric({ label, value }: { label: string; value: string }): JSX.Element {
  return <div className="border-b border-r border-border px-3 py-3 last:border-r-0"><p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-text-muted">{label}</p><p className="mt-1 font-mono text-[18px] font-semibold tabular-nums text-text-primary">{value}</p></div>;
}

function percent(value: number | null): string {
  return value === null ? "—" : `${(value * 100).toFixed(1)}%`;
}
