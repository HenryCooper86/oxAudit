import { Bot, Clipboard, ExternalLink } from "lucide-react";
import type { JSX } from "react";
import { useAppStore } from "../lib/stores";
import type { Finding } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";
import { Button } from "./ui";

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
            <span className="text-[11px] font-medium uppercase tracking-[0.12em] text-text-muted">
              {finding.category === "secret" ? "Secret" : "Vulnerability"}
            </span>
            {finding.cwe && (
              <span className="rounded-sm border border-border bg-surface-tertiary px-1.5 py-0.5 font-mono text-[11px] text-text-muted">
                {finding.cwe}
              </span>
            )}
          </div>
          <h2 className="mt-2 text-[16px] font-semibold leading-snug text-text-primary">{finding.ruleName}</h2>
          <p className="selectable mt-1 break-all font-mono text-[11px] text-text-muted">
            {finding.filePath}:{finding.line}:{finding.column}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <Button
            type="button"
            onClick={discussFinding}
            variant="accent"
            size="md"
          >
            <Bot size={13} aria-hidden="true" />
            Discuss in Assistant
          </Button>
          <button
            type="button"
            onClick={() => onCopy(finding)}
            className="inline-flex items-center gap-1.5 rounded-sm border border-border bg-surface-tertiary px-2.5 py-1.5 text-[12px] font-medium text-text-primary hover:border-border-strong hover:bg-surface-active"
          >
            <Clipboard size={13} aria-hidden="true" />
            Copy finding
          </button>
          <button
            type="button"
            onClick={() => onOpenFile(finding)}
            className="inline-flex items-center gap-1.5 rounded-sm bg-accent px-2.5 py-1.5 text-[12px] font-semibold text-accent-contrast hover:bg-accent-hover"
          >
            <ExternalLink size={13} aria-hidden="true" />
            Open file
          </button>
        </div>
      </div>

      <section aria-labelledby="finding-description" className="mt-5 border-t border-border pt-4">
        <h3 id="finding-description" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">
          Description
        </h3>
        <p className="selectable mt-1.5 text-[13px] leading-relaxed text-text-secondary">{finding.description}</p>
      </section>

      <section aria-labelledby="finding-evidence" className="mt-5">
        <h3 id="finding-evidence" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">
          Evidence
        </h3>
        <div className="selectable mt-2 overflow-x-auto rounded-sm border border-border bg-surface-primary p-3">
          <p className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-text-muted">Match</p>
          <pre className="whitespace-pre-wrap break-all font-mono text-[13px] leading-relaxed text-warning">
            {finding.matchText}
          </pre>
        </div>
        {finding.context && (
          <div className="selectable mt-2 overflow-x-auto rounded-sm border border-border bg-surface-primary p-3">
            <p className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-text-muted">Context</p>
            <pre className="whitespace-pre-wrap font-mono text-[13px] leading-relaxed text-text-secondary">{finding.context}</pre>
          </div>
        )}
      </section>

      <section aria-labelledby="finding-recommendation" className="mt-5 rounded-sm border border-success-border bg-success-subtle p-3">
        <h3 id="finding-recommendation" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-success">
          Recommendation
        </h3>
        <p className="selectable mt-1.5 text-[13px] leading-relaxed text-text-secondary">{finding.recommendation}</p>
      </section>
    </article>
  );
}
