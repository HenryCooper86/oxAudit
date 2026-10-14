import { LatestRequestQueue } from "../../lib/latestRequest";
import type {
  ProjectContext,
  SourceRunMetadata,
  ScanRunSummary,
} from "../../lib/types";

export interface SourceProjectLoad {
  context: ProjectContext;
  run: SourceRunMetadata | null;
  runs: ScanRunSummary[];
}

export interface SourceProjectApi {
  inspectSourceProject(path: string): Promise<ProjectContext>;
  listSourceRuns(projectId: string, limit?: number): Promise<ScanRunSummary[]>;
  loadSourceRunMetadata(runId: string): Promise<SourceRunMetadata>;
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
        ? this.api.loadSourceRunMetadata(runId)
        : context.lastCompletedRunId
          ? this.api.loadSourceRunMetadata(context.lastCompletedRunId).catch(() => null)
          : Promise.resolve(null),
    ]);
    if (!this.requests.isCurrent(token)) return null;
    if (run && run.projectId !== context.projectId)
      throw new Error("Saved source run belongs to a different project.");
    return { context, run, runs };
  }

  invalidate(): void {
    this.requests.invalidate();
  }
}
