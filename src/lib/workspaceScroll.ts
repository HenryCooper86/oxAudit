/** Reveal explicitly activated details without taking focus from the results. */
export function revealWorkspaceDetail(element: HTMLElement | null): void {
  if (!element) return;
  requestAnimationFrame(() => {
    if (!element.isConnected) return;
    const workspace = element.closest("main");
    if (!workspace) return;
    const detailBounds = element.getBoundingClientRect();
    const workspaceBounds = workspace.getBoundingClientRect();
    if (detailBounds.top < workspaceBounds.top || detailBounds.top + Math.min(detailBounds.height, 40) > workspaceBounds.bottom) {
      workspace.scrollTop += detailBounds.top - workspaceBounds.top;
    }
  });
}
