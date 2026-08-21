import { ArrowLeft } from "lucide-react";
import type { JSX, ReactNode } from "react";
import { usePanelCollapsed } from "../../lib/usePanelCollapsed";
import { Button } from "../ui";
import { PanelCollapseButton } from "./PanelCollapseButton";

export function SplitWorkspace(props: {
  panelId: string;
  listLabel: string;
  list: ReactNode;
  detailLabel: string;
  detail: ReactNode;
  hasSelection: boolean;
  onBackToList?: () => void;
}): JSX.Element {
  const { panelId, listLabel, list, detailLabel, detail, hasSelection, onBackToList } = props;
  const [listCollapsed, toggleListCollapsed] = usePanelCollapsed(panelId);
  const listContentId = `${panelId}-content`;

  return (
    <div className={`grid min-h-[28rem] transition-[grid-template-columns] duration-200 motion-reduce:transition-none ${listCollapsed ? "min-[900px]:grid-cols-[44px_minmax(0,1fr)]" : "min-[900px]:grid-cols-[minmax(17rem,0.8fr)_minmax(0,1.35fr)]"}`}>
      <section
        aria-label={listLabel}
        className={`min-w-0 border-border min-[900px]:border-r ${hasSelection ? "max-[900px]:hidden" : ""}`}
      >
        <div className={`hidden h-9 items-center border-b border-border min-[900px]:flex ${listCollapsed ? "justify-center px-1" : "justify-between px-3"}`}>
          {!listCollapsed && (
            <span className="truncate text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">
              {listLabel}
            </span>
          )}
          <PanelCollapseButton
            controls={listContentId}
            expanded={!listCollapsed}
            label={listLabel.toLowerCase()}
            onToggle={toggleListCollapsed}
          />
        </div>
        <div
          id={listContentId}
          className={listCollapsed ? "min-[900px]:hidden" : undefined}
        >
          {list}
        </div>
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
