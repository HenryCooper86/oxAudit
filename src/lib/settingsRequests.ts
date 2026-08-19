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
  saveRequests?: SerializedSettingsWrites;
  saveSettings?: (settings: AppSettings) => Promise<void>;
}

/** Native writes are serialized without suppressing any successful snapshot. */
export class SerializedSettingsWrites {
  private tail: Promise<void> = Promise.resolve();

  run<T>(write: () => Promise<T>): Promise<T> {
    const result = this.tail.then(write, write);
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}

export const persistedSettingsSaveRequests = new SerializedSettingsWrites();

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

interface PersistedPreferenceDependencies {
  saveRequests?: SerializedSettingsWrites;
  saveSettings?: (settings: AppSettings) => Promise<void>;
}

/**
 * Persists a settings change that cannot affect AI readiness — currently the
 * theme. It joins the same write queue as a full save so the two can never
 * interleave, and reads the latest snapshot *inside* the critical section so a
 * save queued ahead of it is never clobbered. Unlike a full save it does not
 * re-run the connection test: flipping the theme should not touch the network.
 */
export async function savePersistedThemePreference(
  readSettings: () => AppSettings | null,
  theme: string,
  publishSettings: (settings: AppSettings) => void,
  dependencies: PersistedPreferenceDependencies = {},
): Promise<AppSettings | null> {
  const saveRequests =
    dependencies.saveRequests ?? persistedSettingsSaveRequests;
  const saveSettings = dependencies.saveSettings ?? api.saveSettings;

  return saveRequests.run(async () => {
    const current = readSettings();
    if (!current || current.theme === theme) return null;

    const next = { ...current, theme };
    await saveSettings(next);
    publishSettings(next);
    return next;
  });
}

export interface SavedSettingsPublication {
  token: RequestToken;
  readiness: Promise<void>;
}

/**
 * Serializes native writes and publishes every successfully persisted snapshot
 * before the next queued write begins.
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

  return saveRequests.run(async () => {
    await saveSettings(settings);
    const token = requests.begin();
    const readiness = publishSavedSettingsSnapshot(
      settings,
      token,
      publishSettings,
      publishReadiness,
      { requests, testAi: dependencies.testAi },
    );
    return readiness ? { token, readiness } : null;
  });
}
