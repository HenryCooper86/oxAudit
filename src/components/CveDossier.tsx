import { Bot, Calendar, ExternalLink, Loader2 } from "lucide-react";
import { useEffect, useRef, useState, type JSX } from "react";
import Markdown from "react-markdown";
import { fmtDateTime } from "../lib/format";
import type { AiReadinessStatus } from "../lib/settingsRequests";
import { useAppStore } from "../lib/stores";
import type { CveDetail } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";
import { InlineState } from "./workbench/InlineState";
import { Button } from "./ui";

export function CveDossier({
  detail,
  loading,
  aiReadiness,
  onOpenUrl,
  onGenerateBriefing,
}: {
  detail: CveDetail | null;
  loading: boolean;
  aiReadiness: AiReadinessStatus;
  onOpenUrl: (url: string) => Promise<void>;
  onGenerateBriefing: () => Promise<string | null>;
}): JSX.Element {
  const openAssistant = useAppStore((state) => state.openAssistant);
  const [briefing, setBriefing] = useState<string | null>(null);
  const [briefingError, setBriefingError] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const briefingRequestRef = useRef(0);
  const aiReady = aiReadiness === "ready";
  const unavailableMessage = {
    loading: "Saved AI settings are still loading.",
    checking: "The newly persisted AI endpoint is still being checked.",
    unconfigured: "Configure an AI provider in Settings to generate a briefing.",
    offline: "The saved AI endpoint is offline. Review Settings before generating a briefing.",
    ready: "",
    unavailable: "AI readiness could not be loaded. Review Settings before generating a briefing.",
  }[aiReadiness];

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

  const discussCve = () => {
    openAssistant({
      id: crypto.randomUUID(),
      label: `CVE dossier: ${item.id}`,
      content: [
        `CVE: ${item.id}`,
        `Severity: ${item.severity ?? "Unknown"}`,
        `CVSS: ${item.cvssScore?.toFixed(1) ?? "Not provided"}`,
        `Description:\n${item.description}`,
        `Affected products:\n${item.affectedProducts.length ? item.affectedProducts.join("\n") : "None provided"}`,
        `CWEs:\n${item.cwes.length ? item.cwes.join("\n") : "None provided"}`,
        `Source references:\n${item.references.length ? item.references.join("\n") : "None provided"}`,
      ].join("\n\n"),
      projectPath: null,
    });
  };

  return (
    <div className="max-h-[39rem] overflow-y-auto p-4">
      <section
        aria-labelledby="cve-overview-heading"
        className="rounded-sm border border-border bg-surface-secondary p-4"
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <h2
              id="cve-overview-heading"
              className="font-mono text-[15px] font-semibold text-text-primary"
            >
              {item.id}
            </h2>
            <SeverityBadge severity={item.severity} />
            {item.cvssScore !== null && (
              <span className="rounded-sm border border-border px-1.5 py-0.5 font-mono text-[11px] text-text-secondary">
                CVSS {item.cvssScore.toFixed(1)}
              </span>
            )}
          </div>
          <Button
            type="button"
            onClick={discussCve}
            variant="accent"
            size="sm"
          >
            <Bot size={12} aria-hidden="true" />
            Discuss in Assistant
          </Button>
        </div>
        <p className="mt-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">
          Overview
        </p>
        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-text-muted">
          <span className="inline-flex items-center gap-1">
            <Calendar size={11} aria-hidden="true" /> Published{" "}
            {fmtDateTime(item.published)}
          </span>
          <span className="inline-flex items-center gap-1">
            <Calendar size={11} aria-hidden="true" /> Modified{" "}
            {fmtDateTime(item.modified)}
          </span>
        </div>
        <p className="selectable mt-3 text-[13px] leading-relaxed text-text-primary">
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
        className="mt-3 rounded-sm border border-border bg-surface-secondary p-4"
      >
        <div className="flex items-center justify-between gap-3">
          <h3
            id="nvd-record-heading"
            className="text-[12px] font-semibold uppercase tracking-[0.12em] text-text-secondary"
          >
            NVD record
          </h3>
          <button
            type="button"
            onClick={() =>
              void onOpenUrl(`https://nvd.nist.gov/vuln/detail/${item.id}`)
            }
            className="inline-flex items-center gap-1.5 rounded-sm border border-border bg-surface-active px-2.5 py-1.5 text-[11px] text-info hover:border-info"
          >
            <ExternalLink size={11} aria-hidden="true" /> Open NVD
          </button>
        </div>
        <p className="mt-2 text-[13px] leading-relaxed text-text-secondary">
          Verified CVE fields above are normalized from NVD. The unmodified NVD
          response remains available for inspection.
        </p>
        <RawRecord label="Show raw NVD record" value={detail.raw} />
      </section>

      <section
        aria-labelledby="osv-record-heading"
        className="mt-3 rounded-sm border border-border bg-surface-secondary p-4"
      >
        <div className="flex items-center justify-between gap-3">
          <h3
            id="osv-record-heading"
            className="text-[12px] font-semibold uppercase tracking-[0.12em] text-text-secondary"
          >
            OSV record
          </h3>
          <button
            type="button"
            onClick={() => void onOpenUrl(`https://osv.dev/vulnerability/${item.id}`)}
            className="inline-flex items-center gap-1.5 rounded-sm border border-border bg-surface-active px-2.5 py-1.5 text-[11px] text-info hover:border-info"
          >
            <ExternalLink size={11} aria-hidden="true" /> Open OSV
          </button>
        </div>
        {detail.osv ? (
          <>
            <p className="mt-2 text-[13px] leading-relaxed text-text-secondary">
              Raw OSV data is source material and is not merged into the
              verified CVE fields.
            </p>
            <RawRecord label="Show raw OSV record" value={detail.osv} />
          </>
        ) : (
          <p className="mt-2 text-[12px] text-text-muted">
            No OSV enrichment is available for this dossier. The source may not
            have a matching record, or OSV could not be reached.
          </p>
        )}
      </section>

      <section
        aria-labelledby="references-heading"
        className="mt-3 rounded-sm border border-border bg-surface-secondary p-4"
      >
        <h3
          id="references-heading"
          className="text-[12px] font-semibold uppercase tracking-[0.12em] text-text-secondary"
        >
          References
        </h3>
        {item.references.length > 0 ? (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {item.references.map((reference) => (
              <button
                key={reference}
                type="button"
                onClick={() => void onOpenUrl(reference)}
                className="inline-flex max-w-full items-center gap-1 rounded-sm border border-border bg-surface-secondary px-2 py-1 text-[11px] text-info hover:border-info"
              >
                <ExternalLink size={10} aria-hidden="true" />
                <span className="truncate">
                  {reference.replace(/^https?:\/\//, "")}
                </span>
              </button>
            ))}
          </div>
        ) : (
          <p className="mt-2 text-[12px] text-text-muted">
            No external references were returned for this record.
          </p>
        )}
      </section>

      <section
        aria-labelledby="ai-briefing-heading"
        className="mt-3 rounded-sm border border-border bg-surface-secondary p-4"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3
            id="ai-briefing-heading"
            className="text-[12px] font-semibold uppercase tracking-[0.12em] text-text-secondary"
          >
            AI briefing
          </h3>
          <Button
            type="button"
            onClick={generateBriefing}
            disabled={!aiReady || aiLoading}
            variant="accent"
            size="sm"
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
          </Button>
        </div>
        {!aiReady && (
          <p className="mt-2 text-[12px] text-text-muted">
            {unavailableMessage}
          </p>
        )}
        {aiLoading && (
          <p aria-live="polite" className="mt-2 text-[12px] text-text-muted">
            Generating an AI briefing…
          </p>
        )}
        {briefingError && (
          <p role="alert" className="mt-2 text-[12px] text-error">
            {briefingError}
          </p>
        )}
        {briefing && (
          <div className="md-body selectable mt-3 text-[13px] leading-relaxed text-text-primary">
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
      <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">
        {label}
      </p>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {values.map((value) => (
          <span
            key={value}
            className="rounded-sm border border-border bg-surface-secondary px-1.5 py-0.5 font-mono text-[11px] text-text-secondary"
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
      <summary className="cursor-pointer text-[12px] text-info hover:underline">
        {label}
      </summary>
      <pre className="selectable mt-2 max-h-72 overflow-auto rounded-sm border border-border bg-surface-primary p-3 font-mono text-[13px] leading-relaxed text-text-secondary">
        {JSON.stringify(value, null, 2) ?? "No raw data was returned."}
      </pre>
    </details>
  );
}
