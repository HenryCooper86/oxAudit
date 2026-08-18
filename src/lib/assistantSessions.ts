import type { LatestRequestQueue, LatestRequestResult, RequestToken } from "./latestRequest";
import type { StoredMessage } from "./types";

export interface RuntimeProjectOutcome {
  runtimePath: string | null;
  unavailablePath: string | null;
  warning: string | null;
}

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

export async function resolveRuntimeProject(
  projectPath: string | null,
  setActiveProject: (path: string | null) => Promise<void>,
): Promise<RuntimeProjectOutcome> {
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
    let warning = `Project is unavailable: ${String(error)}`;
    try {
      await setActiveProject(null);
    } catch (clearError) {
      warning = `Runtime project context could not be cleared: ${String(clearError)}`;
    }
    return {
      runtimePath: null,
      unavailablePath: projectPath,
      warning,
    };
  }
}
