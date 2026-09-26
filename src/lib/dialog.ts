/**
 * Native file dialogs with a stated server-mode refusal: a browser cannot
 * open the server's filesystem picker, and pretending otherwise (an empty
 * result, a silent no-op) would be worse than the message. Pages already
 * surface thrown strings as errors.
 */
import { open as tauriOpen, save as tauriSave } from "@tauri-apps/plugin-dialog";
import { serverMode } from "./transport";

type OpenOptions = Parameters<typeof tauriOpen>[0];
type SaveOptions = Parameters<typeof tauriSave>[0];

function refuse(): never {
  throw "Native file dialogs require the desktop app. Against the headless server, type a path on the server's filesystem instead.";
}

export function open(options: OpenOptions): ReturnType<typeof tauriOpen> {
  if (serverMode) refuse();
  return tauriOpen(options);
}

export function save(options: SaveOptions): ReturnType<typeof tauriSave> {
  if (serverMode) refuse();
  return tauriSave(options);
}
