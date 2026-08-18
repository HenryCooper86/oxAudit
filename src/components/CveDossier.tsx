import { openUrl } from "@tauri-apps/plugin-opener";
import { Bot, Calendar, ExternalLink, Loader2 } from "lucide-react";
import { useEffect, useRef, useState, type JSX } from "react";
import Markdown from "react-markdown";
import { fmtDateTime } from "../lib/format";
import type { CveDetail } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";
import { InlineState } from "./workbench/InlineState";

export function CveDossier({
  detail,
  loading,
  aiReady,
  onGenerateBriefing,
}: {
  detail: CveDetail | null;
  loading: boolean;
  aiReady: boolean;
  onGenerateBriefing: () => Promise<string | null>;
}): JSX.Element {
  const [briefing, setBriefing] = useState<string | null>(null);
  const [briefingError, setBriefingError] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const briefingRequestRef = useRef(0);

  useEffect(() => {
    briefingRequestRef.current += 1;
    setBriefing(null);
    setBriefingError(null);
    setAiLoading(false);
  }, [detail?.item.id]);

  const generateBriefing = async () => {
    if (!aiReady || !detail || aiLoading) return;
    const requestId = ++briefingRequestRef.current;
    setAiLoading(true);
    setBriefingError(null);
    try {
      const generated = await onGenerateBriefing();
      if (requestId !== briefingRequestRef.current) return;
      if (generated) setBriefing(generated);
      else setBriefingError("The AI briefing could not be generated.");
    } catch (error) {
      if (requestId === briefingRequestRef.current)
        setBriefingError(String(error));
    } finally {
      if (requestId === briefingRequestRef.current) setAiLoading(false);
    }
  };

  if (loading) {
    return (
      <InlineState
        tone="running"
        compact
        title="Loading CVE details"
        description="Retrieving the selected NVD and OSV records."
      />
    );
  }

  if (!detail) {
    return (
      <InlineState
        tone="empty"
        compact
        title="Select a CVE result"
        description="Choose a result to inspect its dossier."
      />
    );
  }

  const { item } = detail;

  return (
    <div className="max-h-[39rem] overflow-y-auto p-4">
      <section
        aria-labelledby="cve-overview-heading"
        className="rounded-lg border border-ink-700 bg-ink-900/45 p-4"
      >
        <div className="flex flex-wrap items-center gap-2">
          <h2
            id="cve-overview-heading"
            className="font-mono text-[15px] font-semibold text-stone-100"
          >
            {item.id}
          </h2>
          <SeverityBadge severity={item.severity} />
          {item.cvssScore !== null && (
            <span className="rounded border border-ink-600 px-1.5 py-0.5 font-mono text-[11px] text-stone-300">
              CVSS {item.cvssScore.toFixed(1)}
            </span>
          )}
        </div>
        <p className="mt-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-stone-400">
          Overview
        </p>
        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-stone-400">
          <span className="inline-flex items-center gap-1">
            <Calendar size={11} aria-hidden="true" /> Published{" "}
            {fmtDateTime(item.published)}
          </span>
          <span className="inline-flex items-center gap-1">
            <Calendar size={11} aria-hidden="true" /> Modified{" "}
            {fmtDateTime(item.modified)}
          </span>
        </div>
        <p className="selectable mt-3 text-[13px] leading-relaxed text-stone-200">
          {item.description}
        </p>
        {item.cwes.length > 0 && (
          <MetadataChips label="CWEs" values={item.cwes} />
        )}
        {item.affectedProducts.length > 0 && (
          <MetadataChips
            label="Affected products"
            values={item.affectedProducts}
          />
        )}
      </section>

      <section
        aria-labelledby="nvd-record-heading"
        className="mt-3 rounded-lg border border-ink-700 bg-ink-900/45 p-4"
      >
        <div className="flex items-center justify-between gap-3">
          <h3
            id="nvd-record-heading"
            className="text-[12px] font-semibold uppercase tracking-[0.12em] text-stone-300"
          >
            NVD record
          </h3>
          <button
            type="button"
            onClick={() =>
              openUrl(`https://nvd.nist.gov/vuln/detail/${item.id}`)
            }
            className="inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-750 px-2.5 py-1.5 text-[11px] text-sky-300 hover:border-sky-500/50"
          >
            <ExternalLink size={11} aria-hidden="true" /> Open NVD
          </button>
        </div>
        <p className="mt-2 text-[11px] leading-relaxed text-stone-400">
          Verified CVE fields above are normalized from NVD. The unmodified NVD
          response remains available for inspection.
        </p>
        <RawRecord label="Show raw NVD record" value={detail.raw} />
      </section>

      <section
        aria-labelledby="osv-record-heading"
        className="mt-3 rounded-lg border border-ink-700 bg-ink-900/45 p-4"
      >
        <div className="flex items-center justify-between gap-3">
          <h3
            id="osv-record-heading"
            className="text-[12px] font-semibold uppercase tracking-[0.12em] text-stone-300"
          >
            OSV record
          </h3>
          <button
            type="button"
            onClick={() => openUrl(`https://osv.dev/vulnerability/${item.id}`)}
            className="inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-750 px-2.5 py-1.5 text-[11px] text-sky-300 hover:border-sky-500/50"
          >
            <ExternalLink size={11} aria-hidden="true" /> Open OSV
          </button>
        </div>
        {detail.osv ? (
          <>
            <p className="mt-2 text-[11px] leading-relaxed text-stone-400">
              Raw OSV data is source material and is not merged into the
              verified CVE fields.
            </p>
            <RawRecord label="Show raw OSV record" value={detail.osv} />
          </>
        ) : (
          <p className="mt-2 text-[12px] text-stone-400">
            No OSV enrichment is available for this dossier. The source may not
            have a matching record, or OSV could not be reached.
          </p>
        )}
      </section>

      <section
        aria-labelledby="references-heading"
        className="mt-3 rounded-lg border border-ink-700 bg-ink-900/45 p-4"
      >
        <h3
          id="references-heading"
          className="text-[12px] font-semibold uppercase tracking-[0.12em] text-stone-300"
        >
          References
        </h3>
        {item.references.length > 0 ? (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {item.references.map((reference) => (
              <button
                key={reference}
                type="button"
                onClick={() => openUrl(reference)}
                className="inline-flex max-w-full items-center gap-1 rounded border border-ink-600 bg-ink-850 px-2 py-1 text-[11px] text-sky-300 hover:border-sky-500/50"
              >
                <ExternalLink size={10} aria-hidden="true" />
                <span className="truncate">
                  {reference.replace(/^https?:\/\//, "")}
                </span>
              </button>
            ))}
          </div>
        ) : (
          <p className="mt-2 text-[12px] text-stone-400">
            No external references were returned for this record.
          </p>
        )}
      </section>

      <section
        aria-labelledby="ai-briefing-heading"
        className="mt-3 rounded-lg border border-ink-700 bg-ink-900/45 p-4"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3
            id="ai-briefing-heading"
            className="text-[12px] font-semibold uppercase tracking-[0.12em] text-stone-300"
          >
            AI briefing
          </h3>
          <button
            type="button"
            onClick={generateBriefing}
            disabled={!aiReady || aiLoading}
            className="inline-flex items-center gap-1.5 rounded-md border border-accent-600/50 bg-accent-500/10 px-2.5 py-1.5 text-[11px] font-medium text-accent-300 hover:bg-accent-500/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {aiLoading ? (
              <Loader2 size={12} className="animate-spin" aria-hidden="true" />
            ) : (
              <Bot size={12} aria-hidden="true" />
            )}
            {aiLoading
              ? "Generating…"
              : briefing
                ? "Regenerate briefing"
                : "Generate briefing"}
          </button>
        </div>
        {!aiReady && (
          <p className="mt-2 text-[12px] text-stone-400">
            Configure an AI provider in Settings to generate a briefing.
          </p>
        )}
        {aiLoading && (
          <p aria-live="polite" className="mt-2 text-[12px] text-stone-400">
            Generating an AI briefing…
          </p>
        )}
        {briefingError && (
          <p role="alert" className="mt-2 text-[12px] text-red-300">
            {briefingError}
          </p>
        )}
        {briefing && (
          <div className="md-body selectable mt-3 text-[13px] leading-relaxed text-stone-200">
            <Markdown>{briefing}</Markdown>
          </div>
        )}
      </section>
    </div>
  );
}

function MetadataChips({
  label,
  values,
}: {
  label: string;
  values: string[];
}): JSX.Element {
  return (
    <div className="mt-3">
      <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-stone-400">
        {label}
      </p>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {values.map((value) => (
          <span
            key={value}
            className="rounded border border-ink-600 bg-ink-850 px-1.5 py-0.5 font-mono text-[11px] text-stone-300"
          >
            {value}
          </span>
        ))}
      </div>
    </div>
  );
}

function RawRecord({
  label,
  value,
}: {
  label: string;
  value: unknown;
}): JSX.Element {
  return (
    <details className="mt-3">
      <summary className="cursor-pointer text-[12px] text-sky-300 hover:text-sky-200">
        {label}
      </summary>
      <pre className="selectable mt-2 max-h-72 overflow-auto rounded border border-ink-700 bg-ink-950 p-3 font-mono text-[11px] leading-relaxed text-stone-400">
        {JSON.stringify(value, null, 2) ?? "No raw data was returned."}
      </pre>
    </details>
  );
}
