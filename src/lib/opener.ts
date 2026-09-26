/**
 * External link opening with a browser fallback: the desktop delegates to
 * the OS opener plugin; against the headless server a plain new tab is the
 * same user-visible outcome.
 */
import { openUrl as tauriOpenUrl } from "@tauri-apps/plugin-opener";
import { serverMode } from "./transport";

export async function openUrl(url: string): Promise<void> {
  if (serverMode) {
    window.open(url, "_blank", "noopener,noreferrer");
    return;
  }
  await tauriOpenUrl(url);
}
