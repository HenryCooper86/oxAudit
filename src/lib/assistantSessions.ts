import type { LatestRequestQueue, LatestRequestResult, RequestToken } from "./latestRequest";
import type { StoredMessage } from "./types";

export interface RuntimeProjectOutcome {
  runtimePath: string | null;
  unavailablePath: string | null;
  warning: string | null;
}

interface RuntimeProjectRequest {
  generation: number;
  projectPath: string | null;
  setActiveProject: (path: string | null) => Promise<void>;
}

/**
 * Process-global latest-wins coordinator for native active-project state.
 * Only one mutation may be in flight. A queued request is replaced when a
 * newer generation arrives, and all older callers remain behind the barrier
 * until the latest authoritative mutation (including a current failure clear)
 * settles.
 */
class RuntimeProjectCoordinator {
  private generation = 0;
  private running = false;
  private pending: RuntimeProjectRequest | null = null;
  private waiters = new Map<
    number,
    (outcome: RuntimeProjectOutcome) => void
  >();

  request(
    projectPath: string | null,
    setActiveProject: (path: string | null) => Promise<void>,
  ): Promise<RuntimeProjectOutcome> {
    const generation = ++this.generation;
    const outcome = new Promise<RuntimeProjectOutcome>((resolve) => {
      this.waiters.set(generation, resolve);
    });
    this.pending = { generation, projectPath, setActiveProject };
    if (!this.running) {
      this.running = true;
      void this.drain();
    }
    return outcome;
  }

  private async drain(): Promise<void> {
    while (this.pending) {
      const request = this.pending;
      this.pending = null;
      const outcome = await this.apply(request);
      if (request.generation !== this.generation || this.pending) continue;

      for (const [generation, resolve] of this.waiters) {
        if (generation <= request.generation) {
          this.waiters.delete(generation);
          resolve(outcome);
        }
      }
    }
    this.running = false;
  }

  private async apply(
    request: RuntimeProjectRequest,
  ): Promise<RuntimeProjectOutcome> {
    const { generation, projectPath, setActiveProject } = request;
    if (!projectPath) {
      try {
        await setActiveProject(null);
        return { runtimePath: null, unavailablePath: null, warning: null };
      } catch (error) {
        return {
          runtimePath: null,
          unavailablePath: null,
          warning: `Runtime project context could not be cleared: ${String(error)}`,
        };
      }
    }

    try {
      await setActiveProject(projectPath);
      return { runtimePath: projectPath, unavailablePath: null, warning: null };
    } catch (error) {
      if (generation !== this.generation) {
        return {
          runtimePath: null,
          unavailablePath: projectPath,
          warning: `Project is unavailable: ${String(error)}`,
        };
      }

      let warning = `Project is unavailable: ${String(error)}`;
      try {
        await setActiveProject(null);
      } catch (clearError) {
        warning = `Runtime project context could not be cleared: ${String(clearError)}`;
      }
      return { runtimePath: null, unavailablePath: projectPath, warning };
    }
  }
}

const runtimeProjects = new RuntimeProjectCoordinator();

export async function loadLatestSessionMessages(
  requests: LatestRequestQueue,
  token: RequestToken,
  load: () => Promise<StoredMessage[]>,
): Promise<LatestRequestResult<StoredMessage[]>> {
  const messages = await load();
  return requests.isCurrent(token)
    ? { current: true, value: messages }
    : { current: false };
}

export function resolveRuntimeProject(
  projectPath: string | null,
  setActiveProject: (path: string | null) => Promise<void>,
): Promise<RuntimeProjectOutcome> {
  return runtimeProjects.request(projectPath, setActiveProject);
}
