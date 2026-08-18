import { api } from "./api";
import { LatestRequestQueue, type RequestToken } from "./latestRequest";
import type { AiStatus, AppSettings } from "./types";

export type AiReadinessStatus =
  | "loading"
  | "checking"
  | "unconfigured"
  | "offline"
  | "ready"
  | "unavailable";

export interface AiReadiness {
  status: AiReadinessStatus;
  version: number;
}

/** Shared generation across startup loads and Settings saves/retries. */
export const persistedSettingsRequests = new LatestRequestQueue();

export function loadingAiReadiness(token: RequestToken): AiReadiness {
  return { status: "loading", version: token.generation };
}

export function unavailableAiReadiness(token: RequestToken): AiReadiness {
  return { status: "unavailable", version: token.generation };
}

interface PersistedReadinessDependencies {
  requests?: LatestRequestQueue;
  testAi?: () => Promise<AiStatus>;
}

/**
 * Publishes readiness for one persisted settings snapshot. Configured snapshots
 * synchronously enter `checking`, and stale snapshot completions are discarded.
 */
export async function publishPersistedAiReadiness(
  settings: AppSettings,
  token: RequestToken,
  publish: (readiness: AiReadiness) => void,
  dependencies: PersistedReadinessDependencies = {},
): Promise<void> {
  const requests = dependencies.requests ?? persistedSettingsRequests;
  const testAi = dependencies.testAi ?? api.testAi;
  if (!requests.isCurrent(token)) return;
  if (!settings.ai.enabled || !settings.ai.baseUrl.trim()) {
    publish({ status: "unconfigured", version: token.generation });
    return;
  }

  publish({ status: "checking", version: token.generation });
  let status: "ready" | "offline";
  try {
    status = (await testAi()).ok ? "ready" : "offline";
  } catch {
    status = "offline";
  }
  if (requests.isCurrent(token)) {
    publish({ status, version: token.generation });
  }
}

/**
 * Publishes one successfully saved snapshot only while its request token is
 * current. Readiness enters `checking` synchronously before consumers receive
 * the new settings, preventing the previous provider's ready state leaking
 * into the newly persisted configuration.
 */
export function publishSavedSettingsSnapshot(
  settings: AppSettings,
  token: RequestToken,
  publishSettings: (settings: AppSettings) => void,
  publishReadiness: (readiness: AiReadiness) => void,
  dependencies: PersistedReadinessDependencies = {},
): Promise<void> | null {
  const requests = dependencies.requests ?? persistedSettingsRequests;
  if (!requests.isCurrent(token)) return null;

  const readiness = publishPersistedAiReadiness(
    settings,
    token,
    publishReadiness,
    dependencies,
  );
  publishSettings(settings);
  return readiness;
}
