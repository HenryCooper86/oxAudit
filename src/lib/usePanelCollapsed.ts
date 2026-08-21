import { useCallback, useState } from "react";
import {
  cachePanelCollapsed,
  readPanelCollapsed,
} from "./panelPreference";

export function usePanelCollapsed(
  panelId: string,
  fallback = false,
): readonly [boolean, () => void] {
  const [collapsed, setCollapsed] = useState(() =>
    readPanelCollapsed(panelId, fallback),
  );

  const toggle = useCallback(() => {
    setCollapsed((current) => {
      const next = !current;
      cachePanelCollapsed(panelId, next);
      return next;
    });
  }, [panelId]);

  return [collapsed, toggle] as const;
}
