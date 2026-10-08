import { CalendarClock, Play, RefreshCw } from "lucide-react";
import { listen, type UnlistenFn } from "../lib/events";
import { useEffect, useMemo, useRef, useState, type JSX } from "react";
import { Button, Select, Switch } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { fmtDateTime } from "../lib/format";
import { useToastStore } from "../lib/stores";
import type { RecentProject, ScanScheduleStatus } from "../lib/types";

const INTERVALS: Array<{ hours: number; label: string }> = [
  { hours: 1, label: "Hourly" },
  { hours: 6, label: "Every 6 hours" },
  { hours: 24, label: "Daily" },
  { hours: 168, label: "Weekly" },
  { hours: 720, label: "Monthly" },
];

/**
 * Every project oxAudit knows, its latest evidence, and the re-scan
 * cadence keeping that evidence fresh. The stated limits are on the page,
 * not in a manual: scheduled scans run only while the app is open, one at
 * a time, and a scan that collides with one you started waits out the
 * next scheduler tick rather than fighting it.
 */
export function PortfolioPage(): JSX.Element {
  const push = useToastStore((state) => state.push);
  const [projects, setProjects] = useState<RecentProject[] | null>(null);
  const [schedules, setSchedules] = useState<ScanScheduleStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyProject, setBusyProject] = useState<string | null>(null);
  const mounted = useRef(true);
  const refreshGeneration = useRef(0);

  const refresh = async () => {
    const generation = ++refreshGeneration.current;
    try {
      const [nextProjects, nextSchedules] = await Promise.all([
        api.listSourceProjects(50),
        api.listScanSchedules(),
      ]);
      if (!mounted.current || generation !== refreshGeneration.current) return;
      setProjects(nextProjects);
      setSchedules(nextSchedules);
      setError(null);
    } catch (cause) {
      if (mounted.current && generation === refreshGeneration.current) setError(String(cause));
    }
  };

  useEffect(() => {
    mounted.current = true;
    void refresh();
    let disposed = false;
    let unlisten: UnlistenFn | undefined;
    void listen<{ projectId: string; ok: boolean; findings: number | null; error: string | null }>(
      "schedule://completed",
      (event) => {
        if (disposed) return;
        const { projectId, ok, findings, error: failure } = event.payload;
        if (ok) {
          push("success", `Scheduled scan finished — ${findings ?? 0} finding(s).`);
        } else {
          push("error", `Scheduled scan failed${failure ? `: ${failure}` : "."}`);
        }
        void projectId;
        void refresh();
      },
    ).then((stop) => {
      if (disposed) stop();
      else unlisten = stop;
    }).catch((cause) => {
      if (!disposed) setError(String(cause));
    });
    return () => {
      disposed = true;
      mounted.current = false;
      refreshGeneration.current += 1;
      unlisten?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const scheduleByProject = useMemo(() => {
    const map = new Map<string, ScanScheduleStatus>();
    for (const schedule of schedules ?? []) map.set(schedule.projectId, schedule);
    return map;
  }, [schedules]);

  const saveSchedule = async (
    project: RecentProject,
    intervalHours: number,
    enabled: boolean,
  ) => {
    setBusyProject(project.projectId);
    try {
      await api.setScanSchedule(
        project.projectId,
        project.canonicalPath,
        project.displayName,
        intervalHours,
        enabled,
      );
      await refresh();
    } catch (cause) {
      push("error", "The schedule could not be saved.");
      setError(String(cause));
    } finally {
      setBusyProject(null);
    }
  };

  const removeSchedule = async (project: RecentProject) => {
    setBusyProject(project.projectId);
    try {
      await api.removeScanSchedule(project.projectId);
      await refresh();
    } catch (cause) {
      push("error", "The schedule could not be removed.");
      setError(String(cause));
    } finally {
      setBusyProject(null);
    }
  };

  const scanNow = async (project: RecentProject) => {
    setBusyProject(project.projectId);
    push("info", `Scanning ${project.displayName}…`);
    try {
      const detail = await api.runScanNow(project.projectId, project.canonicalPath);
      if (detail.status !== "completed") {
        push("error", `${project.displayName}: scan did not complete.`);
      } else if (detail.persistence.status !== "saved") {
        push("error", `${project.displayName}: scan completed, but results were not saved.`);
      } else {
        push("success", `${project.displayName}: ${detail.summary.totalFindings} finding(s) in run ${detail.runId.slice(0, 8)}.`);
      }
      await refresh();
    } catch (cause) {
      push("error", `${project.displayName}: scan failed — ${String(cause)}`);
    } finally {
      setBusyProject(null);
    }
  };

  return (
    <ToolPage
      title="Portfolio"
      description="Every project oxAudit knows, its latest evidence, and a re-scan cadence to keep it fresh."
    >
      {error && (
        <InlineState tone="error" title="The portfolio could not be loaded" description={error} />
      )}
      {!projects && !error && <InlineState tone="running" title="Loading portfolio" />}
      {projects && projects.length === 0 && (
        <InlineState
          tone="empty"
          title="No projects yet"
          description="Scan a folder and it appears here with its evidence and staleness."
        />
      )}
      {projects && projects.length > 0 && (
        <section aria-label="Projects" className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
          <ul className="divide-y divide-border">
            {projects.map((project) => {
              const schedule = scheduleByProject.get(project.projectId);
              const busy = busyProject === project.projectId;
              return (
                <li key={project.projectId} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <p className="text-[13px] font-medium text-text-primary">{project.displayName}</p>
                    <p className="mt-0.5 truncate font-mono text-[10px] text-text-muted" title={project.canonicalPath}>
                      {project.canonicalPath}
                    </p>
                    <p className="mt-1 text-[11px] text-text-secondary">
                      {project.lastCompletedAt ? (
                        <>
                          Last scan {fmtDateTime(project.lastCompletedAt)} ·{" "}
                          {project.countsAvailable ? <>
                            <span className="font-medium">{project.openFindings} open</span>
                            {project.critical + project.high > 0 &&
                              ` (${project.critical} critical / ${project.high} high)`}
                          </> : "Finding counts unavailable"}
                        </>
                      ) : (
                        "Never scanned"
                      )}
                    </p>
                    {schedule?.enabled && (
                      <p className="mt-0.5 inline-flex items-center gap-1 text-[11px] text-text-muted">
                        <CalendarClock size={11} aria-hidden="true" />
                        {schedule.nextDueAt
                          ? `Next rescan ${fmtDateTime(schedule.nextDueAt)}`
                          : "Rescans on the next scheduler tick"}
                      </p>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="md"
                      onClick={() => void scanNow(project)}
                      disabled={busy}
                    >
                      {busy ? <RefreshCw size={13} className="animate-spin" aria-hidden="true" /> : <Play size={13} aria-hidden="true" />}
                      {busy ? "Working…" : "Scan now"}
                    </Button>
                    {schedule ? (
                      <>
                        <Select
                          aria-label={`Rescan interval for ${project.displayName}`}
                          variant="compact"
                          value={String(schedule.intervalHours)}
                          disabled={busy}
                          onChange={(event) =>
                            void saveSchedule(project, Number(event.target.value), schedule.enabled)
                          }
                        >
                          {INTERVALS.map((interval) => (
                            <option key={interval.hours} value={interval.hours}>
                              {interval.label}
                            </option>
                          ))}
                        </Select>
                        <Switch
                          checked={schedule.enabled}
                          onChange={(enabled) => void saveSchedule(project, schedule.intervalHours, enabled)}
                          disabled={busy}
                          label={schedule.enabled ? "Rescheduling" : "Off"}
                        />
                        <Button type="button" variant="outline" size="md" onClick={() => void removeSchedule(project)} disabled={busy}>
                          Unschedule
                        </Button>
                      </>
                    ) : (
                      <Button
                        type="button"
                        variant="outline"
                        size="md"
                        onClick={() => void saveSchedule(project, 24, true)}
                        disabled={busy}
                      >
                        <CalendarClock size={13} aria-hidden="true" />
                        Schedule daily
                      </Button>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
          <p className="border-t border-border px-4 py-3 text-[11px] text-text-muted">
            Scheduled scans run only while oxAudit is open, one at a time, through the same engine
            and enabled rule packs as a manual scan. A scheduled scan that collides with one you
            started retries on a later scheduler tick. Scheduled scans do not bypass an invalid project
            policy — the failure surfaces here and in the completion toast.
          </p>
        </section>
      )}
    </ToolPage>
  );
}
