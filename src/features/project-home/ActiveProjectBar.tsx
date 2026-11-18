import { FolderOpen } from "lucide-react";
import type { JSX } from "react";
import { Button } from "../../components/ui";
import { useAppStore } from "../../lib/stores";
import { serverMode } from "../../lib/transport";
import { openProjectFromShell } from "./openProject";

function basename(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

/**
 * oxFuzz's active-project bar: a card with a 3px status stripe naming the
 * project the Dashboard is working on, and the one action that changes it.
 * Accent while nothing is selected, success once a folder is chosen. It shows
 * the selection, not a verdict: whether the folder is readable is Project
 * home's job, directly below.
 */
export function ActiveProjectBar(): JSX.Element {
  const selected = useAppStore((state) => state.selectedProject);
  const requestProjectField = useAppStore((state) => state.requestProjectField);
  const choose = () => {
    if (serverMode) requestProjectField();
    else void openProjectFromShell();
  };
  const actionLabel = serverMode
    ? selected ? "Change path" : "Enter server path"
    : selected ? "Change project…" : "Open project…";

  return (
    <section
      aria-label="Active project"
      className={`surface-card border-l-[3px] px-3.5 py-3 ${selected ? "border-l-success" : "border-l-accent"}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <FolderOpen
            aria-hidden="true"
            size={16}
            className={`shrink-0 ${selected ? "text-success" : "text-accent"}`}
          />
          <div className="flex min-w-0 flex-col">
            <span className="truncate text-[13px] font-medium text-text-primary">
              {selected ? basename(selected) : "No project selected"}
            </span>
            <span className={`truncate text-[12px] text-text-muted ${selected ? "selectable font-mono" : ""}`}>
              {selected ??
                (serverMode
                  ? "Type a folder path on the server in Project home to inspect its history."
                  : "Choose a project folder to inspect its history and run a project check.")}
            </span>
          </div>
        </div>
        <Button variant={selected ? "outline" : "primary"} size="sm" onClick={choose}>
          <FolderOpen aria-hidden="true" size={13} />
          {actionLabel}
        </Button>
      </div>
    </section>
  );
}
