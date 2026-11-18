import { open } from "@tauri-apps/plugin-dialog";
import { errorMessage } from "../../lib/commandError";
import { useAppStore, useToastStore } from "../../lib/stores";
import { serverMode } from "../../lib/transport";

/**
 * The shell's "Open project" action (sidebar and Dashboard project bar).
 *
 * Desktop: the native folder picker, then the same selection Project home's
 * own "Open project" makes (`setSelectedProject`), landing on the Dashboard
 * where Project home inspects it. Cancelling the picker does nothing.
 *
 * Server mode has no native picker (the browser cannot browse the server's
 * filesystem), so it goes to the Dashboard and focuses the typed project
 * folder field instead.
 */
export async function openProjectFromShell(): Promise<void> {
  const store = useAppStore.getState();
  if (serverMode) {
    store.requestProjectField();
    return;
  }
  let selected: string | string[] | null;
  try {
    selected = await open({ directory: true, multiple: false, title: "Open project" });
  } catch (cause) {
    useToastStore
      .getState()
      .push("error", `Could not open the folder picker. ${errorMessage(cause)} Type the project path instead.`);
    store.requestProjectField();
    return;
  }
  if (typeof selected !== "string" || !selected.trim()) return;
  store.setSelectedProject(selected.trim());
  store.setPage("dashboard");
}

/**
 * Switch to a recent project exactly as the command palette does: make it the
 * active project and go to where its findings are.
 */
export function activateRecentProject(path: string): void {
  const store = useAppStore.getState();
  store.setActiveProject(path);
  store.setPage("source-scan");
}
