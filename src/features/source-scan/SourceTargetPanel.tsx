import { Ban, Clock3, FolderClock, Play } from "lucide-react";
import { useCallback, useState, type JSX } from "react";
import { TargetInput } from "../../components/workbench/TargetInput";
import { Button, Switch } from "../../components/ui";
import { InlineState } from "../../components/workbench/InlineState";
import type { ProjectContext, RecentProject, ScanProgress } from "../../lib/types";
import type {
  SourceScanOptionKey,
  SourceScanOptionsState,
  SourceScanOptionValues,
} from "../../lib/sourceScanOptions";
import { fmtDateTime } from "../../lib/format";
import { serverMode } from "../../lib/transport";
import { PolicyStatusView } from "./PolicyStatus";
import { useProjectDrop } from "./useProjectDrop";

export function SourceTargetPanel(props: {
  path: string;
  recentProjects: RecentProject[];
  project: ProjectContext | null;
  options: SourceScanOptionsState;
  running: boolean;
  blocked?: boolean;
  cancelling: boolean;
  dropping: boolean;
  progress: ScanProgress | null;
  rulePackFiles: string;
  onRulePackFilesChange(next: string): void;
  onPathChange(path: string): void;
  onOptionChange<K extends SourceScanOptionKey>(key: K, value: SourceScanOptionValues[K]): void;
  onRun(ignoreInvalidPolicy: boolean): void;
  onCancel(): void;
}): JSX.Element {
  const {
    path,
    recentProjects,
    project,
    options,
    running,
    cancelling,
    dropping: externalDropping,
    rulePackFiles,
    onRulePackFilesChange,
    onPathChange,
    onOptionChange,
    onRun,
    onCancel,
  } = props;
  const [dropUnavailable, setDropUnavailable] = useState(false);
  const onDropError = useCallback(() => setDropUnavailable(true), []);
  const selectDroppedPath = useCallback((nextPath: string) => {
    if (!running && !props.blocked && !serverMode) onPathChange(nextPath);
  }, [onPathChange, props.blocked, running]);
  const { dropping } = useProjectDrop(selectDroppedPath, onDropError);
  const activeDrop = !running && !props.blocked && !serverMode && (externalDropping || dropping);
  const values = options.values;
  const noCategories = !values.scanSecrets && !values.scanVulnerabilities;
  const policyInvalid = project?.policy.status === "invalid";
  const runDisabled = props.blocked || !path.trim() || !project || running || !options.resolved || noCategories || policyInvalid;

  return (
    <section aria-label="Source scan target" className={`rounded-sm border bg-surface-secondary p-4 ${activeDrop ? "border-accent bg-accent-subtle" : "border-border"}`}>
      <div className="grid gap-4 min-[980px]:grid-cols-[minmax(0,1.5fr)_minmax(18rem,0.8fr)]">
        <div className="min-w-0">
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[min(100%,24rem)] flex-1">
              <TargetInput
                value={path}
                onChange={onPathChange}
                disabled={running || props.blocked}
                label="Project folder"
                inputLabel="Project folder path"
                pickers={["folder"]}
                placeholder="Choose a project folder…"
                hint="Source scans support a project folder. Choose Run scan when ready."
              />
            </div>
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              {running && (
                <Button type="button" onClick={onCancel} disabled={cancelling} variant="danger" size="md">
                  <Ban size={13} aria-hidden="true" />
                  {cancelling ? "Cancelling…" : "Cancel"}
                </Button>
              )}
              <Button type="button" onClick={() => onRun(false)} disabled={runDisabled} variant="primary" size="md">
                <Play size={13} aria-hidden="true" />
                {running ? "Scanning…" : "Run scan"}
              </Button>
            </div>
          </div>

          {!serverMode && <p className="mt-2 text-[11px] text-text-muted">
            {activeDrop ? "Drop the folder to inspect it." : dropUnavailable ? "Drag-and-drop is unavailable here; use Choose folder or paste a path." : "You can also drop a project folder anywhere on this window to inspect it."}
          </p>}

          <details className="mt-3 border-t border-border pt-3">
            <summary className="w-fit cursor-pointer text-[12px] font-medium text-text-secondary hover:text-text-primary">
              Advanced scan settings
            </summary>
            <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-3">
              <Switch checked={values.scanSecrets} onChange={(checked) => onOptionChange("scanSecrets", checked)} label="Secrets" disabled={running} />
              <Switch checked={values.scanVulnerabilities} onChange={(checked) => onOptionChange("scanVulnerabilities", checked)} label="Vulnerabilities" disabled={running} />
              <Switch checked={values.includeGit} onChange={(checked) => onOptionChange("includeGit", checked)} label="Include .git" disabled={running} />
              <Switch checked={values.followSymlinks} onChange={(checked) => onOptionChange("followSymlinks", checked)} label="Follow in-project symlinks" disabled={running} />
              <label className="flex items-center gap-2 text-[12px] text-text-secondary">
                Max file size
                <input
                  type="number"
                  value={values.maxFileSizeKb}
                  min={1}
                  max={10240}
                  onChange={(event) => onOptionChange("maxFileSizeKb", Number(event.target.value) || 1024)}
                  disabled={running}
                  className="w-20 rounded-sm border border-border bg-surface-primary px-2 py-1 font-mono text-xs text-text-primary disabled:cursor-not-allowed disabled:opacity-50"
                />
                KB
              </label>
            </div>
            <label className="mt-3 block text-[12px] text-text-secondary">
              Rule pack files (comma-separated paths, applied to this scan only)
              <input
                aria-label="Rule pack files for this scan"
                className="mt-1.5 w-full rounded-sm border border-border bg-surface-primary px-2 py-1 font-mono text-xs text-text-primary disabled:cursor-not-allowed disabled:opacity-50"
                placeholder="/path/to/pack.toml"
                value={rulePackFiles}
                onChange={(event) => onRulePackFilesChange(event.target.value)}
                disabled={running}
              />
              <span className="mt-1 block text-[11px] text-text-muted">
                One-off packs are validated before the scan starts; a pack that fails validation stops the scan. To apply packs to every scan, install them in the Rule Library.
              </span>
            </label>
          </details>

          {project && (
            <div className="mt-3">
              <PolicyStatusView
                policy={project.policy}
                running={running || Boolean(props.blocked)}
                onRunWithoutPolicy={() => onRun(true)}
              />
            </div>
          )}

          {noCategories && !running && (
            <div className="mt-3">
              <InlineState tone="unavailable" compact title="No scan categories selected" description="Enable secrets or vulnerabilities to run a source scan." />
            </div>
          )}
        </div>

        <aside aria-labelledby="recent-projects-title" className="min-w-0 border-t border-border pt-3 min-[980px]:border-l min-[980px]:border-t-0 min-[980px]:pl-4 min-[980px]:pt-0">
          <div className="flex items-center justify-between gap-3">
            <h2 id="recent-projects-title" className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">Recent targets</h2>
            <Clock3 size={14} aria-hidden="true" className="text-text-muted" />
          </div>
          {recentProjects.length === 0 ? (
            <div className="mt-3 flex items-start gap-2 text-[12px] text-text-muted">
              <FolderClock size={15} aria-hidden="true" className="mt-0.5 shrink-0" />
              <p>No previous source scans. Browse or drop a folder to begin.</p>
            </div>
          ) : (
            <div className="mt-2 max-h-52 overflow-y-auto divide-y divide-border">
              {recentProjects.slice(0, 12).map((recent) => {
                const selected = recent.canonicalPath === path;
                const countsAvailable = recent.lastCompletedRunId && recent.countsAvailable !== false;
                return (
                  <button
                    key={recent.projectId}
                    type="button"
                    aria-current={selected ? "true" : undefined}
                    onClick={() => onPathChange(recent.canonicalPath)}
                    disabled={running || props.blocked}
                    className={`w-full px-2 py-2 text-left transition-colors ${selected ? "bg-accent-subtle" : "hover:bg-surface-hover"}`}
                  >
                    <span className="flex items-center justify-between gap-3">
                      <span className="truncate text-[12px] font-medium text-text-primary">{recent.displayName}</span>
                      <span className="shrink-0 font-mono text-[10px] text-text-muted">{countsAvailable ? `${recent.openFindings} open` : recent.lastCompletedRunId ? "Counts unavailable" : "Counts unknown"}</span>
                    </span>
                    <span className="mt-0.5 block truncate font-mono text-[10px] text-text-muted">{recent.canonicalPath}</span>
                    <span className="mt-1 block text-[10px] text-text-muted">
                      {recent.lastCompletedAt ? fmtDateTime(recent.lastCompletedAt) : "Not yet completed"}{countsAvailable ? ` · ${recent.critical + recent.high} critical/high` : ""}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </aside>
      </div>
    </section>
  );
}
