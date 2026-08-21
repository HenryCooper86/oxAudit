import { useEffect, useState } from "react";
import { getCurrentWebview, type DragDropEvent } from "@tauri-apps/api/webview";

export function chooseDroppedPath(event: DragDropEvent): string | null {
  return event.type === "drop" ? (event.paths[0] ?? null) : null;
}

export function useProjectDrop(
  onPath: (path: string) => void,
  onError: (error: unknown) => void,
): { dropping: boolean } {
  const [dropping, setDropping] = useState(false);

  useEffect(() => {
    let disposed = false;
    let reportedError = false;
    let unlisten: (() => void) | null = null;

    const reportError = (error: unknown) => {
      if (!disposed && !reportedError) {
        reportedError = true;
        setDropping(false);
        onError(error);
      }
    };

    try {
      void getCurrentWebview()
        .onDragDropEvent((event) => {
          if (disposed) return;
          if (event.payload.type === "over") {
            setDropping(true);
            return;
          }
          setDropping(false);
          const path = chooseDroppedPath(event.payload);
          if (path) onPath(path);
        })
        .then((release) => {
          if (disposed) release();
          else unlisten = release;
        })
        .catch(reportError);
    } catch (error) {
      // Browser-only previews do not expose Tauri's webview metadata.
      reportError(error);
    }

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [onError, onPath]);

  return { dropping };
}
