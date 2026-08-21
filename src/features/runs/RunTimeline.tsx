import { Check, Circle, LoaderCircle } from "lucide-react";
import type { JSX } from "react";

export type RunTimelineStage =
  | "discovering"
  | "detecting"
  | "normalizing"
  | "enriching"
  | "assessing"
  | "persisting"
  | "completed";

const STAGES: Array<{ id: Exclude<RunTimelineStage, "completed">; label: string }> = [
  { id: "discovering", label: "Discover" },
  { id: "detecting", label: "Detect" },
  { id: "normalizing", label: "Normalize" },
  { id: "enriching", label: "Enrich" },
  { id: "assessing", label: "Assess" },
  { id: "persisting", label: "Save" },
];

export function RunTimeline({ active, running, hasCompletedResult }: { active: RunTimelineStage; running: boolean; hasCompletedResult: boolean }): JSX.Element {
  const activeIndex = active === "completed" ? STAGES.length : STAGES.findIndex((stage) => stage.id === active);
  return (
    <section aria-label="Durable run lifecycle" className="overflow-x-auto rounded-sm border border-border bg-surface-secondary px-3 py-2.5">
      <ol className="flex min-w-[38rem] items-center">
        {STAGES.map((stage, index) => {
          const complete = active === "completed" || index < activeIndex;
          const current = running && index === activeIndex;
          return (
            <li key={stage.id} aria-current={current ? "step" : undefined} className="flex min-w-0 flex-1 items-center text-[10px] text-text-muted">
              <span className={`inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full border ${complete ? "border-success text-success" : current ? "border-accent-glow text-accent" : "border-border text-text-muted"}`}>
                {complete ? <Check size={11} aria-hidden="true" /> : current ? <LoaderCircle size={11} aria-hidden="true" className="animate-spin" /> : <Circle size={8} aria-hidden="true" />}
              </span>
              <span className={`ml-1.5 ${current ? "font-semibold text-text-primary" : ""}`}>{stage.label}</span>
              {index < STAGES.length - 1 && <span aria-hidden="true" className={`mx-2 h-px flex-1 ${index < activeIndex ? "bg-success" : "bg-border"}`} />}
            </li>
          );
        })}
        <li className={`flex items-center gap-1.5 text-[10px] ${active === "completed" ? "font-semibold text-success" : hasCompletedResult ? "text-text-secondary" : "text-text-muted"}`}>
          <Check size={12} aria-hidden="true" />Complete
        </li>
      </ol>
      {running && hasCompletedResult && <p className="mt-2 text-[10px] text-text-muted">A previous completed result remains available while this run advances.</p>}
    </section>
  );
}
