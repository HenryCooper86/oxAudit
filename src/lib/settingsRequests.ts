import { api } from "./api";
import { LatestRequestQueue } from "./latestRequest";
import type { AppSettings } from "./types";

/** Shared generation across startup loads and Settings saves/retries. */
export const persistedSettingsRequests = new LatestRequestQueue();

/** Global readiness always reflects the settings currently persisted natively. */
export async function persistedAiReadiness(
  settings: AppSettings,
): Promise<boolean | null> {
  if (!settings.ai.enabled || !settings.ai.baseUrl.trim()) return null;
  try {
    return (await api.testAi()).ok;
  } catch {
    return false;
  }
}
