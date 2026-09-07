import { LatestRequestQueue } from "../../lib/latestRequest";
import type {
  ProjectContext,
  ScanRunDetail,
  ScanRunSummary,
} from "../../lib/types";

export interface SourceProjectLoad {
  context: ProjectContext;
  run: ScanRunDetail | null;
  runs: ScanRunSummary[];
}

export interface SourceProjectApi {
  inspectSourceProject(path: string): Promise<ProjectContext>;
  listSourceRuns(projectId: string, limit?: number): Promise<ScanRunSummary[]>;
  loadSourceRun(runId: string): Promise<ScanRunDetail>;
}

export class SourceProjectLoader {
  private readonly requests = new LatestRequestQueue();

  constructor(private readonly api: SourceProjectApi) {}

  async load(path: string, runId?: string): Promise<SourceProjectLoad | null> {
    const token = this.requests.begin();
    const context = await this.api.inspectSourceProject(path);
    if (!this.requests.isCurrent(token)) return null;

    const [runs, run] = await Promise.all([
      this.api.listSourceRuns(context.projectId, 50),
      runId
        ? this.api.loadSourceRun(runId)
        : context.lastCompletedRunId
          ? this.api.loadSourceRun(context.lastCompletedRunId).catch(() => null)
          : Promise.resolve(null),
    ]);
    if (!this.requests.isCurrent(token)) return null;
    if (run && run.projectId !== context.projectId)
      throw new Error("Saved source run belongs to a different project.");
    return { context, run, runs };
  }

  async refreshRuns(projectId: string): Promise<ScanRunSummary[] | null> {
    const token = this.requests.begin();
    const runs = await this.api.listSourceRuns(projectId, 50);
    return this.requests.isCurrent(token) ? runs : null;
  }

  invalidate(): void {
    this.requests.invalidate();
  }
}
