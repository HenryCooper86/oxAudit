// Minimal ambient declarations for the Node.js APIs this extension uses.
// Keeping these local avoids a runtime/dev dependency on @types/node; the
// only type dependency is @types/vscode.
declare module 'node:child_process' {
  export interface ExecFileError extends Error {
    code?: string | number;
  }
  export function execFile(
    file: string,
    args: string[],
    options: { cwd?: string; maxBuffer?: number },
    callback: (error: ExecFileError | null, stdout: string, stderr: string) => void,
  ): void;
}
