import { api } from "../../lib/api";
import type {
  CanonicalRun,
  RecentProject,
  ScanRunSummary,
} from "../../lib/types";

export function parseSelectedProject(raw: string | null): string | null {
  try {
    const value: unknown = JSON.parse(raw ?? "null");
    if (!value || typeof value !== "object") return null;
    const stored = value as { version?: unknown; path?: unknown };
    return stored.version === 1 &&
      typeof stored.path === "string" &&
      stored.path.trim() &&
      !stored.path.includes("\0")
      ? stored.path
      : null;
  } catch {
    return null;
  }
}
export interface HomeProject {
  path: string;
  name: string;
  source: RecentProject | null;
  latestSource: ScanRunSummary | null;
  sourceState: string | null;
  newFindings: number | null;
  dependencies: CanonicalRun | null;
  completedDependencies: CanonicalRun | null;
  updatedAt: number;
}
export async function loadProjectHome(): Promise<HomeProject[]> {
  const [projects, canonical] = await Promise.all([
    api.listSourceProjects(50),
    api.listCanonicalRuns(undefined, 200),
  ]);
  const sourceRuns = await Promise.all(
    projects.map((project) => api.listSourceRuns(project.projectId, 50)),
  );
  const canonicalById = new Map(canonical.map((run) => [run.id, run]));
  const homes = new Map<string, HomeProject>();
  projects.forEach((project, index) => {
    const runs = [...sourceRuns[index]].sort(
      (a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt),
    );
    const completed = runs.find(
      (run) => run.runId === project.lastCompletedRunId,
    );
    const latest = runs[0] ?? null;
    homes.set(project.canonicalPath, {
      path: project.canonicalPath,
      name: project.displayName,
      source: project,
      latestSource: latest,
      sourceState: latest
        ? (canonicalById.get(latest.runId)?.state ?? latest.status)
        : null,
      newFindings: completed?.newFindings ?? null,
      dependencies: null,
      completedDependencies: null,
      updatedAt: Math.max(
        Date.parse(project.lastOpenedAt) || 0,
        latest ? Date.parse(latest.startedAt) || 0 : 0,
      ),
    });
  });
  for (const run of [...canonical].sort(
    (a, b) => b.createdAtMs - a.createdAtMs,
  )) {
    if (run.kind !== "dependencies") continue;
    let project = homes.get(run.targetLabel);
    if (!project) {
      project = {
        path: run.targetLabel,
        name:
          run.targetLabel.split(/[\\/]/).filter(Boolean).pop() ??
          run.targetLabel,
        source: null,
        latestSource: null,
        sourceState: null,
        newFindings: null,
        dependencies: null,
        completedDependencies: null,
        updatedAt: run.createdAtMs,
      };
      homes.set(project.path, project);
    }
    project.dependencies ??= run;
    if (run.state === "completed") project.completedDependencies ??= run;
    project.updatedAt = Math.max(project.updatedAt, run.createdAtMs);
  }
  return [...homes.values()].sort((a, b) => b.updatedAt - a.updatedAt);
}
