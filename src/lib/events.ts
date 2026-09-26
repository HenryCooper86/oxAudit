/**
 * Event subscription with a desktop/server split: the Tauri event channel
 * at home, the shared SSE stream against the headless server. Pages import
 * `listen` from here instead of `@tauri-apps/api/event` and cannot tell
 * the difference; tests keep mocking the Tauri module, which this wrapper
 * resolves to in desktop mode.
 */
import { listen as tauriListen } from "@tauri-apps/api/event";
import type { UnlistenFn } from "@tauri-apps/api/event";
import { serverMode, sseListen } from "./transport";

export type { UnlistenFn };

export function listen<T>(
  event: string,
  handler: (event: { payload: T }) => void,
): Promise<UnlistenFn> {
  if (serverMode) {
    return Promise.resolve(sseListen<T>(event, handler));
  }
  // The desktop channel delivers the full Tauri event envelope; our handler
  // contract is the payload-bearing subset every page already uses.
  return tauriListen<T>(event, (tauriEvent) => handler(tauriEvent));
}
