import { FlaskConical, Gauge, RefreshCw, TriangleAlert } from "lucide-react";
import { useCallback, useEffect, useState, type JSX } from "react";
import { Button, SectionLabel } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import type { BenchmarkCounts, ExternalBenchmarkReport, QualityStatus } from "../lib/types";

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

      <ExternalBenchmarkPanel />
      <CompiledGrammarsPanel />
    </ToolPage>
  );
}

/** The GUI face of the CLI's `external-benchmark`: score a local OWASP
 *  Benchmark checkout. The path is the repository root whose
 *  expectedresults CSV carries the ground truth. */
function ExternalBenchmarkPanel(): JSX.Element {
  const [path, setPath] = useState("");
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<ExternalBenchmarkReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async () => {
    const target = path.trim();
    if (!target || running) return;
    setRunning(true);
    setError(null);
    setReport(null);
    try {
      setReport(await api.externalBenchmark(target));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setRunning(false);
    }
  }, [path, running]);

  return (
    <section aria-labelledby="external-benchmark-title" className="rounded-sm border border-border bg-surface-secondary p-4">
      <SectionLabel>External benchmark · OWASP Benchmark</SectionLabel>
      <p className="mt-2 text-[12px] leading-relaxed text-text-secondary">
        Score the scanner against the OWASP Benchmark Project's Java ground truth. Point this at a
        local checkout of the Benchmark repository. Scoring a full checkout can take a while; the
        figures count only the categories oxAudit has Java rules for, and say so for the rest.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        <input
          aria-label="OWASP Benchmark repository path"
          className="min-w-[280px] flex-1 rounded-sm border border-border bg-surface px-2 py-1 text-[13px] text-text-primary"
          placeholder="/path/to/OWASP-Benchmark/Benchmark"
          value={path}
          onChange={(event) => setPath(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") void run();
          }}
          disabled={running}
        />
        <Button type="button" onClick={() => void run()} disabled={running || !path.trim()} variant="outline" size="md">
          <Gauge size={13} aria-hidden="true" />
          {running ? "Scoring…" : "Score benchmark"}
        </Button>
      </div>
      {running && <InlineState tone="running" compact title="Scoring the external benchmark" description="This scans every Benchmark case and can take several minutes." />}
      {error && <InlineState tone="error" compact title="External benchmark failed" description={error} />}
      {report && <ExternalReportView report={report} />}
    </section>
  );
}

function ExternalReportView({ report }: { report: ExternalBenchmarkReport }): JSX.Element {
  const covered = metrics(report.coveredTotals);
  const uncoveredVulnerable = report.uncoveredTotals.truePositives + report.uncoveredTotals.falseNegatives;
  return (
    <div className="mt-4 space-y-3">
      <div aria-label="External benchmark metrics" className="grid grid-cols-2 overflow-hidden rounded-sm border border-border min-[720px]:grid-cols-6">
        <Metric label="Cases" value={String(report.cases)} />
        <Metric label="Covered" value={String(covered.cases)} />
        <Metric label="Precision" value={percent(covered.precision)} />
        <Metric label="Recall" value={percent(covered.recall)} />
        <Metric label="False-positive rate" value={percent(covered.falsePositiveRate)} />
        <Metric label="Youden index" value={covered.youden === null ? "—" : covered.youden.toFixed(3)} />
      </div>
      <p className="text-[12px] leading-relaxed text-text-secondary">
        {report.suite} · {report.runtimeMs} ms. The Youden index (recall − false-positive rate) is
        the Benchmark's own score: flagging everything and flagging nothing both score zero.
      </p>
      {report.uncoveredTotals.trueNegatives + uncoveredVulnerable > 0 && (
        <p className="text-[12px] leading-relaxed text-text-muted">
          {report.uncoveredTotals.trueNegatives + uncoveredVulnerable} uncovered cases
          {" "}{uncoveredVulnerable > 0 && `(${uncoveredVulnerable} vulnerable, necessarily missed)`} are kept
          out of the figures — absent rules, not inaccurate ones.
        </p>
      )}
      <div className="max-h-[28rem] overflow-auto rounded-sm border border-border" aria-label="External benchmark category table">
        <table className="w-full table-fixed border-collapse text-left text-[12px]">
          <caption className="sr-only">Per-category OWASP Benchmark results</caption>
          <thead className="sticky top-0 border-b border-border bg-surface-secondary text-[11px] font-semibold uppercase tracking-[0.1em] text-text-muted">
            <tr>
              <th scope="col" className="px-3 py-2">Category</th>
              <th scope="col" className="px-3 py-2">CWE</th>
              <th scope="col" className="px-3 py-2">TP / FP</th>
              <th scope="col" className="px-3 py-2">TN / FN</th>
              <th scope="col" className="px-3 py-2">Precision</th>
              <th scope="col" className="px-3 py-2">Recall</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {report.categories.map((category) => (
              <tr key={category.category} className={category.covered ? "" : "text-text-muted"}>
                <td className="px-3 py-2 font-medium text-text-primary" title={category.category}>{category.category}</td>
                <td className="px-3 py-2 font-mono">CWE-{category.cwe}</td>
                <td className="px-3 py-2 font-mono tabular-nums">{category.truePositives} / {category.falsePositives}</td>
                <td className="px-3 py-2 font-mono tabular-nums">{category.trueNegatives} / {category.falseNegatives}</td>
                <td className="px-3 py-2 font-mono tabular-nums">{percent(metrics(category).precision)}</td>
                <td className="px-3 py-2 font-mono tabular-nums">{category.covered ? percent(metrics(category).recall) : "no rule"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function metrics(counts: BenchmarkCounts) {
  const flagged = counts.truePositives + counts.falsePositives;
  const real = counts.truePositives + counts.falseNegatives;
  const safe = counts.falsePositives + counts.trueNegatives;
  const precision = flagged > 0 ? counts.truePositives / flagged : null;
  const recall = real > 0 ? counts.truePositives / real : null;
  const falsePositiveRate = safe > 0 ? counts.falsePositives / safe : null;
  const youden = recall !== null && falsePositiveRate !== null ? recall - falsePositiveRate : null;
  return { cases: counts.truePositives + counts.falsePositives + counts.trueNegatives + counts.falseNegatives, precision, recall, falsePositiveRate, youden };
}

function CompiledGrammarsPanel(): JSX.Element {
  const [grammars, setGrammars] = useState<string[] | null>(null);
  useEffect(() => {
    let cancelled = false;
    api.listCompiledGrammars()
      .then((next) => {
        if (!cancelled) setGrammars(next);
      })
      .catch(() => {
        if (!cancelled) setGrammars([]);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section aria-labelledby="compiled-grammars-title" className="rounded-sm border border-border bg-surface-secondary p-4">
      <SectionLabel>Compiled grammars</SectionLabel>
      {grammars === null ? (
        <p className="mt-2 text-[12px] text-text-muted">Loading…</p>
      ) : (
        <>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {grammars.length === 0
              ? <p className="text-[12px] text-text-muted">None — every file is scanned on text alone.</p>
              : grammars.map((grammar) => (
                <span key={grammar} className="rounded-sm border border-border bg-surface-tertiary px-1.5 py-0.5 font-mono text-[11px] text-info">
                  {grammar}
                </span>
              ))}
          </div>
          <p className="mt-2 text-[11px] leading-relaxed text-text-muted">
            A language without a grammar is scanned on text alone: matches in comments and string
            literals are reported rather than suppressed.
          </p>
        </>
      )}
    </section>
  );
}

function Metric({ label, value }: { label: string; value: string }): JSX.Element {
  return <div className="border-b border-r border-border px-3 py-3 last:border-r-0"><p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-text-muted">{label}</p><p className="mt-1 font-mono text-[18px] font-semibold tabular-nums text-text-primary">{value}</p></div>;
}

function percent(value: number | null): string {
  return value === null ? "—" : `${(value * 100).toFixed(1)}%`;
}
