import { useEffect, useRef, useState } from "react";
import { FolderPicker } from "../../components/FolderPicker";
import { Button } from "../../components/ui";
import { normalizeCommandError } from "../../lib/commandError";
import { api } from "../../lib/api";
import { resolveRuntimeProject } from "../../lib/assistantSessions";
import { fmtDateTime } from "../../lib/format";
import { useAppStore } from "../../lib/stores";
import type { ProjectContext, DependencyScanResult } from "../../lib/types";
import { loadProjectHome, type HomeProject } from "./history";
import {
  cancelActiveScan,
  startProjectCheck,
  useScanWorkStore,
} from "./coordinator";

export function ProjectHome() {
  const selected = useAppStore((state) => state.selectedProject);
  const settings = useAppStore((state) => state.settings);
  const setSelected = useAppStore((state) => state.setSelectedProject);
  const openProject = useAppStore((state) => state.openProject);
  const active = useScanWorkStore((state) => state.active);
  const check = useScanWorkStore((state) => state.check);
  const [input, setInput] = useState(selected ?? "");
  const [projects, setProjects] = useState<HomeProject[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [context, setContext] = useState<ProjectContext | null>(null);
  const [selectionError, setSelectionError] = useState<string | null>(null);
  const [selecting, setSelecting] = useState(false);
  const [revision, setRevision] = useState(0);
  const generation = useRef(0);
  useEffect(() => {
    let current = true;
    setLoading(true);
    setLoadError(null);
    void loadProjectHome()
      .then((value) => {
        if (current) setProjects(value);
      })
      .catch((error) => {
        if (current) setLoadError(normalizeCommandError(error).message);
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [revision, check?.status]);
  useEffect(() => {
    const token = ++generation.current;
    setInput(selected ?? "");
    setContext(null);
    setSelectionError(null);
    setSelecting(Boolean(selected));
    if (!selected) return;
    void (async () => {
      try {
        const inspected = await api.inspectSourceProject(selected);
        if (generation.current !== token) return;
        const outcome = await resolveRuntimeProject(
          inspected.canonicalPath,
          api.setActiveProject,
        );
        if (generation.current !== token) return;
        useAppStore.getState().setActiveProject(outcome.runtimePath);
        if (outcome.runtimePath !== inspected.canonicalPath)
          throw new Error(outcome.warning ?? "Project unavailable");
        setContext(inspected);
      } catch (error) {
        if (generation.current === token)
          setSelectionError(normalizeCommandError(error).message);
      } finally {
        if (generation.current === token) setSelecting(false);
      }
    })();
    return () => {
      generation.current += 1;
    };
  }, [selected, revision]);
  const choose = (path: string) => {
    if (path.trim() === selected) setRevision((value) => value + 1);
    else setSelected(path.trim() || null);
  };
  const current = projects.find(
    (project) => project.path === (context?.canonicalPath ?? selected),
  );
  const displayedCheck =
    check?.path === (context?.canonicalPath ?? selected) ? check : null;
  const resume = (
    family: "source-scan" | "deps-scan",
    runId?: string,
    dependencyResult?: DependencyScanResult,
  ) => {
    if (!context) return;
    setSelected(context.canonicalPath);
    openProject(context.canonicalPath, family, runId, dependencyResult);
  };
  return (
    <section
      aria-label="Project home"
      className="space-y-4 text-[13px] text-text-secondary"
    >
      <div className="rounded-sm border border-border bg-surface-secondary p-4 space-y-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-[13px] font-semibold">Your project</h2>
          <Button
            variant="outline"
            onClick={() => setRevision((value) => value + 1)}
          >
            Refresh projects
          </Button>
        </div>
        <FolderPicker value={input} onChange={setInput} />
        <Button
          variant="outline"
          disabled={!input.trim()}
          onClick={() => choose(input)}
        >
          Open project
        </Button>
        {selecting && <p role="status">Inspecting selected project…</p>}
        {selectionError && (
          <p role="alert" className="text-error">
            Project unavailable: {selectionError}. Choose a folder or refresh to
            retry.
          </p>
        )}
        {context && (
          <>
            <div>
              <h3 className="font-semibold text-text-primary">
                {context.displayName}
              </h3>
              <p className="break-all font-mono text-[12px] text-text-muted">
                {context.canonicalPath}
              </p>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 text-[13px]">
              <div>
                <p>Source: {current?.sourceState ?? "not checked"}</p>
                {current?.source?.lastCompletedRunId ? (
                  <>
                    <p>
                      Last checked:{" "}
                      {current.source.lastCompletedAt
                        ? fmtDateTime(current.source.lastCompletedAt)
                        : "time unavailable"}
                    </p>
                    {current.source.countsAvailable === false ? (
                      <p>Source counts: unavailable — refresh when the project is accessible.</p>
                    ) : (
                      <p>
                        {current.source.openFindings} source open ·{" "}
                        {current.source.critical} critical · {current.source.high}{" "}
                        high
                      </p>
                    )}
                    <p>
                      New source findings: {current.newFindings ?? "unknown"}
                    </p>
                    <p className="text-text-muted">
                      Counts reflect the last completed source run.
                    </p>
                  </>
                ) : (
                  <p>Source counts: unknown</p>
                )}
              </div>
              <div>
                <p>
                  Dependencies: {current?.dependencies?.state ?? "not checked"}
                </p>
                <p>
                  Last checked:{" "}
                  {current?.completedDependencies
                    ? fmtDateTime(
                        new Date(
                          current.completedDependencies.updatedAtMs,
                        ).toISOString(),
                      )
                    : "never completed"}
                </p>
                <p>
                  Dependency findings: unknown — open saved results for counts
                  and coverage.
                </p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="primary"
                disabled={Boolean(active)}
                onClick={() =>
                  void startProjectCheck(
                    context.canonicalPath,
                    settings?.scan ?? null,
                  )
                }
              >
                Check project
              </Button>
              <Button
                variant="outline"
                onClick={() =>
                  resume(
                    current?.source?.lastCompletedRunId || current?.latestSource
                      ? "source-scan"
                      : current?.dependencies
                        ? "deps-scan"
                        : "source-scan",
                  )
                }
              >
                Resume project
              </Button>
              <Button variant="outline" onClick={() => resume("source-scan")}>
                Source results
              </Button>
              <Button variant="outline" onClick={() => resume("deps-scan")}>
                Dependency results
              </Button>
            </div>
            <p className="text-[12px] text-text-muted">
              Check project uses saved source options, then discovers lockfiles
              and checks dependencies. No scan runs automatically.
            </p>
          </>
        )}
        {!selected && (
          <p className="text-[13px] text-text-muted">
            Choose a project folder to inspect its history and run a project
            check.
          </p>
        )}
        {displayedCheck && (
          <div
            role="status"
            className="border-t border-border pt-3 text-[13px] space-y-2"
          >
            <h3>Project check {displayedCheck.status}</h3>
            <p>
              Source: {displayedCheck.source} · Dependencies:{" "}
              {displayedCheck.dependencies}
            </p>
            {displayedCheck.error && (
              <p className="text-error">{displayedCheck.error}</p>
            )}
            {displayedCheck.status !== "completed" && (
              <p>
                Result links retain the last available results; they do not
                establish a successful current check.
              </p>
            )}
            <div className="flex gap-2">
              {displayedCheck.sourceResult && (
                <Button
                  variant="outline"
                  onClick={() =>
                    resume("source-scan", displayedCheck.sourceResult?.runId)
                  }
                >
                  View source findings
                </Button>
              )}
              {displayedCheck.dependencyResult && (
                <Button
                  variant="outline"
                  onClick={() =>
                    resume(
                      "deps-scan",
                      undefined,
                      displayedCheck.dependencyResult,
                    )
                  }
                >
                  View dependency findings
                </Button>
              )}
              {displayedCheck.status === "running" && (
                <Button
                  variant="danger"
                  disabled={active?.cancelling}
                  onClick={() => void cancelActiveScan()}
                >
                  Cancel project check
                </Button>
              )}
            </div>
            {displayedCheck.source === "completed, not saved" && (
              <p>
                Source results were not saved. View source findings to inspect
                them and retry saving.
              </p>
            )}
            {displayedCheck.status === "failed" && (
              <Button
                variant="outline"
                onClick={() => useAppStore.getState().setPage("settings")}
              >
                Review Settings
              </Button>
            )}
          </div>
        )}
      </div>
      <div className="space-y-2">
        <h2 className="text-[13px] font-semibold">Recent projects</h2>
        {loading && <p role="status">Loading project history…</p>}
        {loadError && (
          <p role="alert" className="text-error">
            Project history unavailable: {loadError}. Refresh projects to retry.
          </p>
        )}
        {!loading && !loadError && projects.length === 0 && (
          <p className="text-[13px] text-text-muted">
            No saved projects. Choose a folder to begin.
          </p>
        )}
        {projects.map((project) => (
          <button
            key={project.path}
            type="button"
            aria-current={project.path === selected ? "true" : undefined}
            onClick={() => choose(project.path)}
            className="block w-full rounded-sm border border-border bg-surface-secondary p-3 text-left hover:bg-surface-hover"
          >
            <span className="font-medium text-[13px]">{project.name}</span>
            <span className="block break-all font-mono text-[12px] text-text-muted">
              {project.path}
            </span>
            <span className="block text-[12px] text-text-muted">
              Source {project.sourceState ?? "not checked"} · Dependencies{" "}
              {project.dependencies?.state ?? "not checked"}
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}
