import { ArrowLeft } from "lucide-react";
import type { JSX, ReactNode } from "react";

export function SplitWorkspace(props: {
  listLabel: string;
  list: ReactNode;
  detailLabel: string;
  detail: ReactNode;
  hasSelection: boolean;
  onBackToList?: () => void;
}): JSX.Element {
  const { listLabel, list, detailLabel, detail, hasSelection, onBackToList } = props;

  return (
    <div className="grid min-h-[28rem] min-[900px]:grid-cols-[minmax(17rem,0.8fr)_minmax(0,1.35fr)]">
      <section
        aria-label={listLabel}
        className={`min-w-0 border-ink-700 min-[900px]:border-r ${hasSelection ? "max-[900px]:hidden" : ""}`}
      >
        {list}
      </section>
      <section
        aria-label={detailLabel}
        className={`min-w-0 ${hasSelection ? "" : "max-[900px]:hidden"}`}
      >
        {hasSelection && onBackToList && (
          <div className="border-b border-ink-700 px-3 py-2 min-[900px]:hidden">
            <button
              type="button"
              onClick={onBackToList}
              className="inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-750 px-2.5 py-1.5 text-[12px] font-medium text-stone-200 hover:border-ink-500 hover:bg-ink-700"
            >
              <ArrowLeft size={13} aria-hidden="true" />
              Back to findings
            </button>
          </div>
        )}
        {detail}
      </section>
    </div>
  );
}
