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

interface PersistedSaveDependencies extends PersistedReadinessDependencies {
  saveRequests?: LatestRequestQueue;
  saveSettings?: (settings: AppSettings) => Promise<void>;
}

/** Save attempts are ordered independently from the currently persisted snapshot. */
export const persistedSettingsSaveRequests = new LatestRequestQueue();

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

export interface SavedSettingsPublication {
  token: RequestToken;
  readiness: Promise<void>;
}

/**
 * Saves a candidate without disturbing readiness ownership. Only the latest
 * successfully persisted candidate claims a new settings generation and
 * synchronously publishes its checking/unconfigured state.
 */
export async function savePersistedSettingsSnapshot(
  settings: AppSettings,
  publishSettings: (settings: AppSettings) => void,
  publishReadiness: (readiness: AiReadiness) => void,
  dependencies: PersistedSaveDependencies = {},
): Promise<SavedSettingsPublication | null> {
  const requests = dependencies.requests ?? persistedSettingsRequests;
  const saveRequests =
    dependencies.saveRequests ?? persistedSettingsSaveRequests;
  const saveSettings = dependencies.saveSettings ?? api.saveSettings;
  const saveToken = saveRequests.begin();

  const saved = await saveRequests.run(saveToken, async () => {
    try {
      await saveSettings(settings);
    } catch (error) {
      return { status: "failed" as const, error };
    }
    if (!saveRequests.isCurrent(saveToken)) {
      return { status: "stale" as const };
    }

    const token = requests.begin();
    const readiness = publishSavedSettingsSnapshot(
      settings,
      token,
      publishSettings,
      publishReadiness,
      { requests, testAi: dependencies.testAi },
    );
    return readiness
      ? { status: "saved" as const, publication: { token, readiness } }
      : { status: "stale" as const };
  });
  if (!saved.current) return null;
  if (saved.value.status === "failed") throw saved.value.error;
  return saved.value.status === "saved" ? saved.value.publication : null;
}
