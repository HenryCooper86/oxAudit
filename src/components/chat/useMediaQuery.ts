import { useSyncExternalStore } from "react";

function supported(): boolean {
  return typeof window !== "undefined" && typeof window.matchMedia === "function";
}

/** Whether `query` currently matches, re-rendering when that changes. */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      if (!supported()) return () => undefined;
      const list = window.matchMedia(query);
      list.addEventListener?.("change", onChange);
      return () => list.removeEventListener?.("change", onChange);
    },
    () => (supported() ? Boolean(window.matchMedia(query)?.matches) : false),
    () => false,
  );
}
