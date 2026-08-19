import { ArrowLeft } from "lucide-react";
import type { JSX, ReactNode } from "react";
import { Button } from "../ui";

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
        className={`min-w-0 border-border min-[900px]:border-r ${hasSelection ? "max-[900px]:hidden" : ""}`}
      >
        {list}
      </section>
      <section
        aria-label={detailLabel}
        className={`min-w-0 ${hasSelection ? "" : "max-[900px]:hidden"}`}
      >
        {hasSelection && onBackToList && (
          <div className="border-b border-border px-3 py-2 min-[900px]:hidden">
            <Button
              type="button"
              onClick={onBackToList}
              variant="outline"
              size="md"
            >
              <ArrowLeft size={13} aria-hidden="true" />
              Back to findings
            </Button>
          </div>
        )}
        {detail}
      </section>
    </div>
  );
}
