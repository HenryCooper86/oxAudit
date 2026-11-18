/**
 * Host and OS detection for platform-conditional window chrome.
 *
 * The desktop window on macOS uses the overlay title bar, so the traffic
 * lights float over the top-left of the webview. The shell reserves room for
 * them only there; Windows and Linux keep their native title bars, and the
 * headless server's browser build has no window chrome at all.
 *
 * `main.tsx` stamps the result on `<html>` (`data-host`, `data-platform`)
 * before React mounts, so CSS can scope the macOS rules without a flash.
 */

export type HostPlatform = "macos" | "windows" | "linux" | "unknown";
export type HostKind = "tauri" | "web";

interface NavigatorLike {
  platform?: string;
  userAgent?: string;
}

export function detectPlatform(
  nav: NavigatorLike | null = typeof navigator === "undefined" ? null : navigator,
): HostPlatform {
  if (!nav) return "unknown";
  const signature = `${nav.platform ?? ""} ${nav.userAgent ?? ""}`.toLowerCase();
  if (signature.includes("mac")) return "macos";
  if (signature.includes("win")) return "windows";
  if (signature.includes("linux") || signature.includes("x11")) return "linux";
  return "unknown";
}

export function detectHost(
  win: { __TAURI_INTERNALS__?: unknown } | null = typeof window === "undefined" ? null : window,
): HostKind {
  return win?.__TAURI_INTERNALS__ ? "tauri" : "web";
}

/** True only inside the macOS desktop window, where the traffic lights overlay the webview. */
export function isMacDesktopHost(): boolean {
  return detectHost() === "tauri" && detectPlatform() === "macos";
}

export function applyHostAttributes(root: HTMLElement): void {
  root.dataset.host = detectHost();
  root.dataset.platform = detectPlatform();
}
