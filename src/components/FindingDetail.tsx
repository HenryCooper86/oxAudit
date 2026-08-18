import { Bot, Clipboard, ExternalLink } from "lucide-react";
import type { JSX } from "react";
import { useAppStore } from "../lib/stores";
import type { Finding } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";

export function FindingDetail({
  finding,
  onCopy,
  onOpenFile,
}: {
  finding: Finding;
  onCopy: (finding: Finding) => void;
  onOpenFile: (finding: Finding) => void;
}): JSX.Element {
  const activeProject = useAppStore((state) => state.activeProject);
  const openAssistant = useAppStore((state) => state.openAssistant);

  const discussFinding = () => {
    const evidence = [
      `Match:\n${finding.matchText}`,
      finding.context ? `Context:\n${finding.context}` : null,
    ]
      .filter(Boolean)
      .join("\n\n");

    openAssistant({
      id: crypto.randomUUID(),
      label: `Finding: ${finding.ruleName}`,
      content: [
        `Finding: ${finding.ruleName}`,
        `Severity: ${finding.severity}`,
        `Location: ${finding.filePath}:${finding.line}:${finding.column}`,
        `Description:\n${finding.description}`,
        `Evidence:\n${evidence}`,
        `Recommendation:\n${finding.recommendation}`,
      ].join("\n\n"),
      projectPath: activeProject,
    });
  };

  return (
    <article className="p-4 sm:p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <span className="text-[11px] font-medium uppercase tracking-[0.12em] text-stone-400">
              {finding.category === "secret" ? "Secret" : "Vulnerability"}
            </span>
            {finding.cwe && (
              <span className="rounded border border-ink-600 bg-ink-800 px-1.5 py-0.5 font-mono text-[11px] text-stone-400">
                {finding.cwe}
              </span>
            )}
          </div>
          <h2 className="mt-2 text-[16px] font-semibold leading-snug text-stone-100">{finding.ruleName}</h2>
          <p className="selectable mt-1 break-all font-mono text-[11px] text-stone-400">
            {finding.filePath}:{finding.line}:{finding.column}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={discussFinding}
            className="inline-flex items-center gap-1.5 rounded-md border border-accent-600/60 bg-accent-500/10 px-2.5 py-1.5 text-[12px] font-medium text-accent-300 hover:bg-accent-500/20"
          >
            <Bot size={13} aria-hidden="true" />
            Discuss in Assistant
          </button>
          <button
            type="button"
            onClick={() => onCopy(finding)}
            className="inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-750 px-2.5 py-1.5 text-[12px] font-medium text-stone-200 hover:border-ink-500 hover:bg-ink-700"
          >
            <Clipboard size={13} aria-hidden="true" />
            Copy finding
          </button>
          <button
            type="button"
            onClick={() => onOpenFile(finding)}
            className="inline-flex items-center gap-1.5 rounded-md bg-accent-500 px-2.5 py-1.5 text-[12px] font-semibold text-ink-950 hover:bg-accent-400"
          >
            <ExternalLink size={13} aria-hidden="true" />
            Open file
          </button>
        </div>
      </div>

      <section aria-labelledby="finding-description" className="mt-5 border-t border-ink-800 pt-4">
        <h3 id="finding-description" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-stone-400">
          Description
        </h3>
        <p className="selectable mt-1.5 text-[13px] leading-relaxed text-stone-300">{finding.description}</p>
      </section>

      <section aria-labelledby="finding-evidence" className="mt-5">
        <h3 id="finding-evidence" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-stone-400">
          Evidence
        </h3>
        <div className="selectable mt-2 overflow-x-auto rounded-md border border-ink-700 bg-ink-950 p-3">
          <p className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-stone-400">Match</p>
          <pre className="whitespace-pre-wrap break-all font-mono text-[11px] leading-relaxed text-orange-300/90">
            {finding.matchText}
          </pre>
        </div>
        {finding.context && (
          <div className="selectable mt-2 overflow-x-auto rounded-md border border-ink-800 bg-ink-950 p-3">
            <p className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-stone-400">Context</p>
            <pre className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-stone-400">{finding.context}</pre>
          </div>
        )}
      </section>

      <section aria-labelledby="finding-recommendation" className="mt-5 rounded-md border border-emerald-900/60 bg-emerald-950/20 p-3">
        <h3 id="finding-recommendation" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-emerald-400">
          Recommendation
        </h3>
        <p className="selectable mt-1.5 text-[13px] leading-relaxed text-stone-300">{finding.recommendation}</p>
      </section>
    </article>
  );
}
